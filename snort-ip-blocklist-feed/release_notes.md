#### What's Fixed

- Resolved an issue where the connector was unable to retrieve indicators due to a terms and conditions acceptance page on Snort. The connector now programmatically accepts the terms before attempting to download the IP block list.
- Added a new parameter, "Terms and Conditions" in the Connector Configuration. This parameter is enabled by default to automatically accept (Snort's - Testing IP Block List Terms and Conditions).