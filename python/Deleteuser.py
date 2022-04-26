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

def GetPaginatedResponse(url,api_token):
    headers = {'Accept':'application/json','Content-Type':'application/json','Authorization':api_token}
    response = requests.request("GET", url, headers=headers)
    returnResponseList = []
    responseJSON = json.dumps(response.json())
    responseList = json.loads(responseJSON)
    returnResponseList = returnResponseList + responseList
    if "errorCode" in responseJSON:
        print ("\nYou encountered following Error: \n")
        print (responseJSON)
        print ("\n")
        return "Error"
    else:
        headerLink= response.headers["Link"]
        while str(headerLink).find("rel=\"next\"") > -1:
            linkItems = str(headerLink).split(",")
            nextCursorLink = ""
            for link in linkItems:
                if str(link).find("rel=\"next\"") > -1:
                    nextCursorLink = str(link)
            nextLink = str(nextCursorLink.split(";")[0]).strip()
            nextLink = nextLink[1:]
            nextLink = nextLink[:-1]
            url = nextLink
            response = requests.request("GET", url, headers=headers)
            responseJSON = json.dumps(response.json())
            responseList = json.loads(responseJSON)
            returnResponseList = returnResponseList + responseList
            headerLink= response.headers["Link"]
        returnJSON = json.dumps(returnResponseList)
        return returnResponseList


def DELETERequest(url,api_token):
    headers = {'Accept':'application/json','Content-Type':'application/json','Authorization':api_token}
    response = requests.delete(url, headers=headers)
    responseJSON = response
    if "errorCode" in responseJSON:
        print ("\nYou encountered following Error: \n")
        print (responseJSON)
        print ("\n")
        return "Error"
    else:
        return responseJSON


def DeleteUsers(org):
    api_token = "SSWS "+ config['OrgConfig'][org]
    ##### CSV Files #####
     # Deactive Users
    deactiveUsers = open("Deactive-Users.csv", "w")
    deactiveWriter = csv.writer(deactiveUsers)
    deactiveWriter.writerow(["firstName", "lastName", "email", "login", "status"])
    #Deleted Users
    deletedUsers = open("Deleted-Users.csv", "w")
    deletedWriter = csv.writer(deletedUsers)
    deletedWriter.writerow(["firstName", "lastName", "email", "login", "status"])
     #Not Deleted Users
    notDeletedUsers = open("Not-Deleted-Users.csv", "w")
    notDeletedWriter = csv.writer(notDeletedUsers)
    notDeletedWriter.writerow(["firstName", "lastName", "login", "error"])
    ##### CSV Files #####
    url = "https://"+org+"/api/v1/users?filter=status eq \"DEPROVISIONED\""
    deactivedUsers = GetPaginatedResponse(url,api_token)
    userInfoList = []
    abc=[]
    deactivedUsersCount = 0
    deletedUsersCount = 0
    notDeletedUserCount = 0
    userstatus = "No users to Delete"
    for user in deactivedUsers:
        userId = str(user["id"])
        abc.append(str(user["profile"]["login"]))
        deleteUrl = "https://"+org+"/api/v1/users/"+userId
        deactiveWriter.writerow([user["profile"]["firstName"], user["profile"]["lastName"], user["profile"]["email"], user["profile"]["login"], user["status"]])
        deactivedUsersCount += 1
        response = DELETERequest(deleteUrl,api_token)
        response = str(response)
        print(response)
        if response == "<Response [204]>":
            print (str(user["profile"]["login"]) + " is Deleted")
            userstatus = (str(user["profile"]["login"]) + " is Deleted")
            deletedUsersCount += 1
            deletedWriter.writerow([user["profile"]["firstName"], user["profile"]["lastName"], user["profile"]["email"], user["profile"]["login"], user["status"]])
        else:
            notDeletedUserCount += 1
            notDeletedWriter.writerow([user["profile"]["firstName"], user["profile"]["lastName"], user["profile"]["login"], response])
    print ("Deactivated Users: " + str(deactivedUsersCount))
    print ("Deleted Users: " + str(deletedUsersCount))
    print ("Not Deleted Users: " + str(notDeletedUserCount))
    print(userstatus)
    oktaresult = {}
    oktaresult["deactivated_users"] = deactivedUsersCount
    oktaresult["del_users"] = deletedUsersCount
    oktaresult["non_del_users"] = notDeletedUserCount
    oktaresult["user_status"] = abc
    return oktaresult

if __name__ == "__main__":
	print (DeleteUsers())
