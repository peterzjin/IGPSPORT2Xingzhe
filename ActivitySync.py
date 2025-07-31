import base64
from datetime import datetime
from zoneinfo import ZoneInfo
import os
import requests, json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import garth
import zipfile
import hashlib
from stravalib import Client
from stravaweblib import WebClient, DataFormat

def encrpt(password, public_key):
    rsa = RSA.importKey(public_key)
    cipher = PKCS1_v1_5.new(rsa)
    return base64.b64encode(cipher.encrypt(password.encode())).decode()

def syncData(username, password, garmin_email = None, garmin_password = None, strava_jwt = None, strava_api = None):
    headers = {
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
        "Accept-Encoding" : "gzip, deflate",
    }

    igp_host = "my.igpsport.com"
    if os.getenv("IGPSPORT_REGION") == "global":
        igp_host = "i.igpsport.com"

    session = requests.session()
    stype = 1 #default igp

    if garmin_password is not None and garmin_password != '':
        stype = 2 #garmin

    if strava_jwt is not None and strava_jwt != '':
        stype = 3 #strava

    # login account
    if stype == 2:
        print("同步佳明数据")

        garth.configure(domain="garmin.cn")
        garth.login(garmin_email, garmin_password)
        activities = garth.connectapi(
            f"/activitylist-service/activities/search/activities",
            params={"activityType": "cycling", "limit": 10, "start": 0, 'excludeChildren': False},
        )
    elif stype == 3:
        strava_client_id, strava_client_secret, strava_refresh_token = strava_api.strip().split(",")
        tokens = Client().refresh_access_token(strava_client_id, strava_client_secret, strava_refresh_token)
        client = WebClient(access_token=tokens['access_token'], jwt=strava_jwt)
        activities = client.get_activities(limit=10)
    else:
        print("同步IGP数据")

        url = "https://%s/Auth/Login" % igp_host
        data = {
            'username': username,
            'password': password,
        }
        res = session.post(url, data, headers=headers)

        # get igpsport list
        url = "https://%s/Activity/ActivityList" % igp_host
        res = session.get(url)
        result = json.loads(res.text, strict=False)

        activities = result["item"]

    # login xingzhe account
    encrypter_public_key    = "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDmuQkBbijudDAJgfffDeeIButq\nWHZvUwcRuvWdg89393FSdz3IJUHc0rgI/S3WuU8N0VePJLmVAZtCOK4qe4FY/eKm\nWpJmn7JfXB4HTMWjPVoyRZmSYjW4L8GrWmh51Qj7DwpTADadF3aq04o+s1b8LXJa\n8r6+TIqqL5WUHtRqmQIDAQAB\n-----END PUBLIC KEY-----\n"
    safe_password           = encrpt(password, encrypter_public_key)
    
    url     = "https://www.imxingzhe.com/api/v1/user/login/"
    data    = {
        'account': username, 
        'password': safe_password, 
    }
    res     = session.post(url, json=data, headers=headers)
    if res.status_code != 200:
        print("行者登录失败")
        return False
    result  = json.loads(res.text, strict=False)
    print("用户名:%s" % result['data']['username'])

    # get current month data
    url     = "https://www.imxingzhe.com/api/v1/pgworkout/?offset=0&limit=10&sport=3&year=&month="
    res     = session.get(url, headers=headers)
    result  = json.loads(res.text, strict=False)
    data  = result["data"]["data"]

    sync_data = []
    # get not upload activity
    timezone = ZoneInfo('Asia/Shanghai')  # to Shanghai timezero in Gtihub Action env

    for activity in activities:
        if stype == 2: #garmin
            dt        = datetime.strptime(activity["startTimeLocal"], "%Y-%m-%d %H:%M:%S")
            dt2       = datetime(dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second, tzinfo=timezone)
            s_time    = dt2.timestamp()
            mk_time   = int(s_time) * 1000
        elif stype == 3: #strava
            mk_time   = activity.start_date.timestamp() * 1000
        else:
            dt        = datetime.strptime(activity["StartTime"], "%Y-%m-%d %H:%M:%S")
            dt2       = datetime(dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second, tzinfo=timezone)
            s_time    = dt2.timestamp()
            mk_time   = int(s_time) * 1000

        need_sync = True

        for item in data:
            if abs(mk_time - item["start_time"]) < 100000:
                need_sync = False
                break
        if need_sync:
            sync_data.append(activity)

    if len(sync_data) == 0:

        print("nothing data need sync")

    else:
        #down file
        upload_url = "https://www.imxingzhe.com/api/v1/fit/upload/"
        for sync_item in sync_data:
            if stype == 2:  # garmin
                rid     = sync_item['activityId']
                rid = str(rid)
                print("sync rid:" + rid)
                res = garth.download(
                    f"/download-service/files/activity/{rid}",
                )
                with open(rid+".zip", "wb") as f:
                    f.write(res)
                with zipfile.ZipFile(rid+".zip", 'r') as zip_ref:
                    zip_ref.extractall(rid)
                with open(rid+"/"+rid+"_ACTIVITY.fit", 'rb') as fd:
                    data = fd.read()
                    result = session.post(upload_url, files={
                        "file_source": (None, "undefined", None),
                        "fit_filename": (None, rid+"_ACTIVITY.fit", None),
                        "md5": (None, hashlib.md5(data).hexdigest(), None),
                        "name": (None, 'Garmin-' + sync_item["startTimeLocal"], None),
                        "sport": (None, 3, None),  # 骑行
                        "fit_file": (rid+"_ACTIVITY.fit", data, 'application/octet-stream')
                    })
            if stype == 3:  # strava
                data = client.get_activity_data(sync_item.id, fmt=DataFormat.ORIGINAL)
                start_time = sync_item.start_date_local.strftime("%Y-%m-%d %H:%M:%S")
                content = b''.join(data.content)
                result = session.post(upload_url, files={
                    "file_source": (None, "undefined", None),
                    "fit_filename": (None, start_time+'.fit', None),
                    "md5": (None, hashlib.md5(content).hexdigest(), None),
                    "name": (None, 'STRAVA-'+start_time, None),
                    "sport": (None, 3, None),  # 骑行
                    "fit_file": (start_time+'.fit', content, 'application/octet-stream')
                })
                print("Updata STRAVA-"+start_time+": " + str(result.status_code))
            else:
                rid     = sync_item["RideId"]
                rid     = str(rid)
                print("sync rid:" + rid)

                fit_url = "https://%s/fit/activity?type=0&rideid=%s" % (igp_host, rid)
                res     = session.get(fit_url)

                result = session.post(upload_url, files={
                    "file_source": (None, "undefined", None),
                    "fit_filename": (None, sync_item["StartTime"]+'.fit', None),
                    "md5": (None, hashlib.md5(res.content).hexdigest(), None),
                    "name": (None, 'IGPSPORT-'+sync_item["StartTime"], None),
                    "sport": (None, 3, None),  # 骑行
                    "fit_file": (sync_item["StartTime"]+'.fit', res.content, 'application/octet-stream')
                })

activity = syncData(os.getenv("USERNAME"), os.getenv("PASSWORD"), os.getenv("GARMIN_EMAIL"), os.getenv("GARMIN_PASSWORD"), os.getenv("STRAVA_JWT"), os.getenv("STRAVA_API"))
