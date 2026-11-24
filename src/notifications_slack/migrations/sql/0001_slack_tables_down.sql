-- Undo 0001 of the Slack module without CASCADE: an object that depends on these tables makes the downgrade abort.
REVOKE ALL ON slack_thread, slack_delivery, slack_digest_item FROM slack_module;
DROP TABLE slack_digest_item, slack_delivery, slack_thread;
