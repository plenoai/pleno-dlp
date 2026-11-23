package connectors

import (
	"context"
	"fmt"
	"hash"
	neturl "net/url"
)

// slackSearchMaxPages bounds search pagination (Slack caps search at 100
// pages of 100 results).
const slackSearchMaxPages = 100

type slackSearchPaging struct {
	Page  int `json:"page"`
	Pages int `json:"pages"`
}

type slackSearchMessagesResp struct {
	OK       bool   `json:"ok"`
	Error    string `json:"error"`
	Messages struct {
		Matches []struct {
			slackMessage
			Channel slackChannelInfo `json:"channel"`
		} `json:"matches"`
		Paging slackSearchPaging `json:"paging"`
	} `json:"messages"`
}

type slackSearchFile struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	URLPrivateDownload string   `json:"url_private_download"`
	Permalink          string   `json:"permalink"`
	Channels           []string `json:"channels"`
	Groups             []string `json:"groups"`
	IMs                []string `json:"ims"`
	Timestamp          int64    `json:"timestamp"`
}

type slackSearchFilesResp struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
	Files struct {
		Matches []slackSearchFile `json:"matches"`
		Paging  slackSearchPaging `json:"paging"`
	} `json:"files"`
}

// slackSearchHint explains the scope Slack search requires; bot tokens
// cannot call search.* at all.
func slackSearchHint(code string) string {
	switch code {
	case "not_allowed_token_type":
		return code + " (search requires a user token, xoxp-, with search:read)"
	case "missing_scope":
		return code + " (search requires search:read; file download requires files:read)"
	}
	return code
}

// slackSearch pages search.messages and search.files for query, visiting
// each message match and each file match. maxResults <= 0 means no cap
// beyond Slack's own page limit.
func slackSearch(ctx context.Context, cli *slackClient, query string, maxResults int, visitMsg func(slackChannelInfo, slackMessage) error, visitFile func(slackChannelInfo, slackSearchFile) error) error {
	seen := 0
	for page := 1; page <= slackSearchMaxPages; page++ {
		var resp slackSearchMessagesResp
		path := fmt.Sprintf("/api/search.messages?query=%s&count=100&page=%d", neturl.QueryEscape(query), page)
		if err := cli.getJSON(ctx, path, &resp); err != nil {
			return fmt.Errorf("search.messages: %w", err)
		}
		if !resp.OK {
			return fmt.Errorf("search.messages: %s", slackSearchHint(resp.Error))
		}
		for _, m := range resp.Messages.Matches {
			if maxResults > 0 && seen >= maxResults {
				break
			}
			seen++
			if err := visitMsg(m.Channel, m.slackMessage); err != nil {
				return err
			}
		}
		if (maxResults > 0 && seen >= maxResults) || resp.Messages.Paging.Pages <= page {
			break
		}
	}
	seen = 0
	for page := 1; page <= slackSearchMaxPages; page++ {
		var resp slackSearchFilesResp
		path := fmt.Sprintf("/api/search.files?query=%s&count=100&page=%d", neturl.QueryEscape(query), page)
		if err := cli.getJSON(ctx, path, &resp); err != nil {
			return fmt.Errorf("search.files: %w", err)
		}
		if !resp.OK {
			return fmt.Errorf("search.files: %s", slackSearchHint(resp.Error))
		}
		for _, f := range resp.Files.Matches {
			if maxResults > 0 && seen >= maxResults {
				break
			}
			seen++
			ch := slackChannelInfo{}
			for _, ids := range [][]string{f.Channels, f.Groups, f.IMs} {
				if len(ids) > 0 && ch.ID == "" {
					ch.ID = ids[0]
				}
			}
			if err := visitFile(ch, f); err != nil {
				return err
			}
		}
		if (maxResults > 0 && seen >= maxResults) || resp.Files.Paging.Pages <= page {
			break
		}
	}
	return nil
}

// scanSlackSearch emits every message and file matched by query, reusing
// the per-message and per-file incremental bookkeeping of channel scans.
func scanSlackSearch(ctx context.Context, cli *slackClient, query string, maxResults int, state *slackScanState, emit Emit) error {
	return slackSearch(ctx, cli, query, maxResults,
		func(ch slackChannelInfo, msg slackMessage) error {
			return emitSlackMessageIncremental(ctx, ch, msg, state, emit)
		},
		func(ch slackChannelInfo, f slackSearchFile) error {
			msg := slackMessage{TS: fmt.Sprintf("%d", f.Timestamp), Permalink: f.Permalink}
			name := f.Name
			if f.Permalink != "" {
				name = f.Permalink
			}
			return emitSlackFileIncremental(ctx, cli, ch, msg, f.ID, name, f.URLPrivateDownload, state, emit)
		})
}

func fingerprintSlackSearch(ctx context.Context, h hash.Hash, cli *slackClient, query string, maxResults int) error {
	return slackSearch(ctx, cli, query, maxResults,
		func(ch slackChannelInfo, msg slackMessage) error {
			fingerprintSlackMessage(h, ch, msg)
			return nil
		},
		func(ch slackChannelInfo, f slackSearchFile) error {
			writeFingerprint(h, "search-file")
			writeFingerprint(h, f.ID)
			writeFingerprint(h, f.Name)
			writeFingerprint(h, f.URLPrivateDownload)
			writeFingerprint(h, fmt.Sprintf("%d", f.Timestamp))
			return nil
		})
}
