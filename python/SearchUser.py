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
# def SEARCHRequest(url):
#     response = requests.get(url, headers=headers)
#     responseJSON = response
#     if "errorCode" in responseJSON:
#         print ("\nYou encountered following Error: \n")
#         print (responseJSON)
#         print ("\n")
#         return "Error"
#     else:
#         return responseJSON


def SearchUsers(query,list,field,con,org):
    list=list.split(',')
    ##### CSV Files #####
     # Deactive Users
    # deactiveUsers = open("Deactive-Users.csv", "w")
    # deactiveWriter = csv.writer(deactiveUsers)
    # deactiveWriter.writerow(["firstName", "lastName", "email", "login", "status"])
    # #Deleted Users
    # deletedUsers = open("Deleted-Users.csv", "w")
    # deletedWriter = csv.writer(deletedUsers)
    # deletedWriter.writerow(["firstName", "lastName", "email", "login", "status"])
    #  #Not Deleted Users
    # notDeletedUsers = open("Not-Deleted-Users.csv", "w")
    # notDeletedWriter = csv.writer(notDeletedUsers)
    # notDeletedWriter.writerow(["firstName", "lastName", "login", "error"])
    ##### CSV Files #####
    url = "https://"+org+"/api/v1/users?search=profile."+ field + " " + con + " \""+ query +"\" and (status eq \"ACTIVE\" OR status eq \"PROVISIONED\" or status eq  \"STAGED\")"
    api_token = "SSWS "+ config['OrgConfig'][org]
    deactivedUsers = GetPaginatedResponse(url,api_token)
    print(deactivedUsers)
    fn = []
    ln = []
    abc=[]
    oktaresult = []
    oktaresult1 = []
    deactivedUsersCount = 0
    deletedUsersCount = 0
    notDeletedUserCount = 0
    userstatus = "No users to Delete"
    for user in deactivedUsers:
        if user["status"] == "ACTIVE" or user["status"] == "PROVISIONED" or user["status"] == "STAGED":
            oktaresult1.append(user["profile"])
            oktaresult.append("{"+"\"user\":"+"\"" +str(user["profile"]["login"])+"\""+",\"fn\":"+"\""+str(user["profile"]["firstName"])+"\""+",\"ln\":"+"\""+str(user["profile"]["lastName"]+"\""+"}"))
            acount=''
            first="true"
            for i in list:
                if len(i)!=0:
                    if i not in user["profile"]:
                        # print(i)
                        user["profile"][i]=""
                    if first=="true":
                        first="false"
                        acount+=("\""+i+"\":\""+str(user["profile"][i])+"\"")
                    else :
                        # print(user["profile"][i])
                        acount+=(",\""+i+"\":\""+str(user["profile"][i])+"\"")
            if "login" in acount:
                abc.append("{"+acount+"}")
            else:
                abc.append("{"+acount+",\"login\":\"" +str(user["profile"]["login"])+"\""+"}")
        # abc.append(str(user["profile"]["login"]))
        # fn.append(str(user["profile"]["firstName"]))
        # ln.append(str(user["profile"]["lastName"]))
    return oktaresult1

if __name__ == "__main__":
    SearchUsers()
