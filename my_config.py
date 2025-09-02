#!/usr/bin/python3
### Api
user = 'api'
password = 'apiapiapi'

domain_name = ''
url = '5.2.6.1'

api_wait_time=1
page_size=20
publish_wait_time=1

### Colors
OBJECT_COLOR = 'red'

### 
target_url = "http://localhost/i/object_sync_test.json"
auth_username = "myuser"
auth_password = "mypassword"

#Only specific groups will be synced
RESTRICTED_GROUPS = True
ALLOWED_SYNC_GROUPS = ['SOC_SYNC_TEST','SOC_SYNC_TEST_ESP']

#Run only during non working hours
NON_WORKING_HOURS_ONLY = False

#Networks with smaller masks shouldn't be synced
MIN_V4_MASK_LENGTH=20
MIN_V6_MASK_LENGTH=64

#Objects shouldn't be in these networks
RAW_DISALLOWED_NETWORKS = [
    '10.0.0.0/8',
    ]

