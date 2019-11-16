# Slack IAM Notifier
Encourage good IAM credentials for Security Hub / CIS Compliance (with added slack notifications)  

# What does it do?
This simple python script will query IAM to output to Slack a list of users who's keys are beyond the 90 days reccomended by CIS guidance. It'll also name and shame when users do not have MFA (or 2FA) enabled on their console accounts. 

# What should I do with this? 
Firstly, I'm not responsible if you disable keys that are needed for production access. So check this code first before you run it on your AWS environment. You're responsible for what you run on your AWS environments.  

# Using & Preparing your machine
To get your environment ready, ensure you have configured your AWS config locally aka `aws configure`. The key and secret you provided will need to have IAM full access for it to be used to it's full potential. 

Install requirements:
`pip install -r requirements.txt` 

Check the script 
- Things to be aware of is that this will delete keys older than 90 days. No checks, no questions. It'll do it. If you don't want this then comment out the line `disablekey(UserName, Key['AccessKeyId'])`. 
- You need to provide a SlackWebhook URL so it can send messages to Slack with it's findings.
- Add some tags to your users on IAM. This way the script can talk to them directly rather than a generic message in a channel. Create a tag called `slack_username` with the value being the IAM User's slack username. Boom. Nice. 
- Exclusion lists are there for a reason. If you want to protect some users (you'll still fail CIS for this). Then add to the array on line 12 entitled `exclude_list`. Stick thier UserName in there and the script will skip them on all checks. 
- Groups are good. So if you have some bots, or production Access Keys etc. Add them to a group and that group can be bypassed too aka replace bot with in this command with the group name: `if 'bot' in group_list:`
- You're done! 

Let's run it!
`python main.py` 


Huzzah, congratulations on patronising your IAM users into CIS complience. 
