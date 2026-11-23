Owners: qa

Assemble the fake MongoDB Atlas SRV URI in `pkg/blastradius/database` tests at runtime. The literal `mongodb+srv://svc:password@cluster0.acme.mongodb.net/` added in #921/#922 raised a GitHub secret-scanning alert (MongoDB Atlas Database URI with credentials) although it is a dummy.
