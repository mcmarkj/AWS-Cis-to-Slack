import boto3
import datetime
import json
import requests

# Slack Webhook URL
hook_url = ''

# Exclusion List

exclude_list = ['Root']

# Set today's date as var
today = datetime.datetime.now()

# Create IAM client
iam = boto3.client('iam')


def checkkeys(User):
    access_keys = iam.list_access_keys(UserName=User)

    if len(access_keys['AccessKeyMetadata']) < 1:
        pass

    for Key in access_keys['AccessKeyMetadata']:
        create_date = Key['CreateDate']
        create_date = create_date.replace(tzinfo=None)

        key_age = today - create_date

        if int(key_age.days) > 89:
            msg = """
            *{username}'s
            AWS Key:{key} is {days} days old,
            key has now been disabled.*
            """.format(username=getslackusername(User),
                       key=Key['AccessKeyId'],
                       days=key_age.days)

            # Sending alert to Slack.
            slackalert(msg)

            # Disabling the key to keep CIS compliance
            disablekey(UserName, Key['AccessKeyId'])

        elif int(key_age.days) > 76:
            msg = """
            * {username}'s
            AWS Key:{key} is {days} days old,
            please renew this urgently.*
            """.format(username=getslackusername(User),
                       key=Key['AccessKeyId'],
                       days=key_age.days)

            slackalert(msg)


def disablekey(user, key):
    print("Disabling Key: {} for User: {}").format(key, user)
    iam.delete_access_key(UserName=user, AccessKeyId=key)


def checkmfa(User):
    try:
        profile = iam.get_login_profile(UserName=User)
        profile.CreateDate
        devices = iam.list_mfa_devices(UserName=User)
        if not devices['MFADevices']:
            msg = """
            *User {} doesn't have 2FA enabled on AWS. Please enable urgently.*
            """.format(getslackusername(User))
            slackalert(msg)
    except:
        # User doesn't have Console Access. Skipping.
        return False


def getslackusername(User):
    # If tags are used on AWS. You can specify a user's slack Username in iam
    # this way, they'll be mentioned.
    # Otherwise, it'll default to their UserName

    tags = iam.list_user_tags(UserName=User)

    for tag in tags['Tags']:

        if tag['Key'] == 'slack_username':
            # This will run if the slack_username value is found.
            # We're formatting the string so Slack uses it as a mention.
            name = "<@{}>".format(tag['Value'])
            return name
        else:
            # Not the tag we want, so skipping.
            continue

    # Nothing was found so we're defaulting to their iam UserName.
    return User


def slackalert(msg):
    slack_body = {'text': msg}

    response = requests.post(
        hook_url, data=json.dumps(slack_body),
        headers={'Content-Type': 'application/json'}
    )


# Get a list of users from IAM
users = iam.list_users()

# Loop the array and print their username
for User in users['Users']:

    UserName = User['UserName']

    # Check exclusion list determined at top of script

    if UserName in exclude_list:
        continue

    # Check users groups, if they're a member
    # of an exclusion group then ignore.
    groups = iam.list_groups_for_user(UserName=UserName)

    group_list = []

    for group in groups['Groups']:
        group_list.append(group['GroupName'])

    # If you use groups, and your bots are in a group.
    # Then replace `Bots` with the group name to bypass.

    if 'Bots' in group_list:
        continue

    # 1.2 Ensure multi-factor authentication (MFA) is enabled for all IAM
    # users that have a console password

    checkmfa(UserName)

    # 1.4 Ensure access keys are rotated every 90 days or less
    checkkeys(UserName)
