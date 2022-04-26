import requests, json, re, sys, csv, configparser
config = configparser.ConfigParser(allow_no_value=True)
config.optionxform = str
config.read('application.properties')
# import openpyxl
# orgName = "vigneshl.okta"
# apiKey = "00Kxndul6N7j0nGmT86ZIBeKSoKtpTop3wCdUYntkI"
# orgName = "cloudok.oktapreview"
# apiKey = "00o1d1HJU8WYfYHFoxdL1gUy6M378aPy8JHNjSi78r"
# orgchart={"vigneshl.okta.com":"00Kxndul6N7j0nGmT86ZIBeKSoKtpTop3wCdUYntkI","cloudok.oktapreview.com":"00o1d1HJU8WYfYHFoxdL1gUy6M378aPy8JHNjSi78r"}

def DeactivateUsers(user_list,org):
    user_list=user_list.split(',')
    print(user_list)
    oktaresult = []
    api_token = "SSWS "+ config['OrgConfig'][org]
    headers = {'Accept':'application/json','Content-Type':'application/json','Authorization':api_token}
    for user in user_list:
        if len(user)!=0:
            url = "https://"+org+"/api/v1/users/" + user +"/lifecycle/deactivate"
            print(url)
            response = requests.post(url, headers=headers)
            responseJSON=response.json();
            if "errorCode" in responseJSON:
                oktaresult.append("Error: User "+user+" is not found")
    return oktaresult

if __name__ == "__main__":
    DeactivateUsers()
