#### What's Fixed

- Resolved an issue where the connector was unable to fetch indicators due to the presence of a terms and conditions acceptance page on Snort. The connector now programmatically accepts the terms before attempting to download the IP block list.
- Added new parameter `Terms and Conditions` in connector configuration.