import requests, json, re, sys, csv, configparser
config = configparser.ConfigParser(allow_no_value=True)
config.optionxform = str
config.read('application.properties')
# orgName = "vigneshl.okta"
# apiKey = "00Kxndul6N7j0nGmT86ZIBeKSoKtpTop3wCdUYntkI"
# orgchart={"vigneshl.okta.com":"00Kxndul6N7j0nGmT86ZIBeKSoKtpTop3wCdUYntkI","cloudok.oktapreview.com":"00o1d1HJU8WYfYHFoxdL1gUy6M378aPy8JHNjSi78r"}
def CreateUsers(N,M,fn,ln,dn,org):
    firstName = fn
    lastName = ln
    domain=dn
    userList=[]
    counter=0
    oktaResponse={}
    ## CSV file before user is created
    # beforeCreation = open("User-Info-Before-Creation.csv", "wb")
    # beforeWriter = csv.writer(beforeCreation)
    # beforeWriter.writerow(["firstName", "lastName", "email", "login"])
    # afterCreation = open("User-Info-After-Creation.csv", "wb")
    # afterWriter = csv.writer(afterCreation)
    # afterWriter.writerow(["id", "status", "email","Okta-Request-Id"])
    for userNum in range(N,N+M):
        try:
            email = firstName.lower()+lastName.lower()+str(userNum)+"@"+domain
            ## First name of the user
            print ("\n Creating User " + email + "\n")
            #Write to CSV before creating
            # beforeWriter.writerow([firstName,lastName,email,email])
            user_info = {}
            user_info['profile'] = {}
            user_info['credentials'] = {}
            user_info['profile'] ['firstName'] = firstName
            user_info['profile'] ['lastName'] = lastName
            user_info['profile'] ['email'] = email
            user_info['profile'] ['login'] = email
            user_info['credentials'] ['password'] = {}
            user_info['credentials'] ['recovery_question'] = {}
            user_info['credentials'] ['password']['value'] = "Okta@1234"
            user_info['credentials']['recovery_question'] ['question'] = "Who's a major player"
            user_info['credentials']['recovery_question'] ['answer'] = "pickles"
            user_info_json = json.dumps(user_info)
            url = "https://"+org+"/api/v1/users"
            api_token = "SSWS "+ config['OrgConfig'][org]
            headers = {'Accept':'application/json','Content-Type':'application/json','Authorization':api_token}
            print (user_info)
            response = requests.post(url, data = user_info_json, headers = headers)
            responseJSON = response.json()
            if (response.status_code) == 200:
                userList.append(email + " has been created successfully")
                counter+=1
            elif (response.status_code) == 400:
                userList.append("User creation with login " + email + " failed :" + responseJSON['errorCauses'][0]['errorSummary'])
            print(response.status_code)
            ##Read headers
            oktaRequestId= response.headers["X-Okta-Request-Id"]
            print (str(userNum) + " user  created")
            if "errorCode" in  responseJSON:
                print (responseJSON['errorCauses'][0]['errorSummary'])
            else:
                userId = responseJSON["id"]
                status = responseJSON["status"]
                userEmail = responseJSON["profile"]["email"]
                #Write to CSV after creating
                # afterWriter.writerow([userId,status,email,oktaRequestId])
        except:
            print ("Unexpected error:", sys.exc_info())
            print ("\n")
    oktaResponse ["userList"] = userList
    oktaResponse ["count"] = counter
    return oktaResponse

if __name__ == "__main__":
    CreateUsers()
