import requests
import json
import re
import sys
import csv
# import openpyxl



orgName = "vigneshl.okta"
apiKey = "00Kxndul6N7j0nGmT86ZIBeKSoKtpTop3wCdUYntkI"

api_token = "SSWS "+ apiKey

headers = {'Accept':'application/json','Content-Type':'application/json','Authorization':api_token}



def GetPaginatedResponse(url):

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



def GETRequest(url):

    response = requests.get(url, headers=headers)

    responseJSON = response.json()

    if "errorCode" in responseJSON:
        print ("\nYou encountered following Error: \n")
        print (responseJSON)
        print ("\n")

        return "Error"

    else:

        return responseJSON


def EnrolledUsers():


    ##### CSV Files #####

     # Deactive Users
    userFactors = open("./static/Enrolled-Users.csv", "w",newline='')

    userWriter = csv.writer(userFactors)

    userWriter.writerow(["First Name", "Last Name", "Email", "Login", "Factor"])

    ##### CSV Files #####

    url = "https://"+orgName+".com/api/v1/users?search=profile.firstName sw \"Script\" AND status eq \"ACTIVE\""

    listUsers = GetPaginatedResponse(url)

    for user in listUsers:

        userId = str(user["id"])

        enrolledUsersUrl = "https://"+orgName+".com/api/v1/users/"+userId+"/factors"

        response = GETRequest(enrolledUsersUrl)

        # response = str(response)
        # print(response)
        # print(response[0]['factorType'])
        if response == [] :
            userWriter.writerow([user["profile"]["firstName"], user["profile"]["lastName"], user["profile"]["email"], user["profile"]["login"]])
        else:
            counter=0

            for k in response:
                # print(response[counter]['factorType'])
                if response[counter]['factorType']=='question':
                    factor='Security Question'
                elif response[counter]['factorType']=='push':
                    factor='Okta Verify with Push'
                elif response[counter]['factorType']=='token:software:totp' and response[counter]['provider']=='OKTA':
                    factor='Okta Verify Soft Token'
                elif response[counter]['factorType']=='call':
                    factor='Voice Call Authentication'
                elif response[counter]['factorType']=='sms':
                    factor='SMS Authentication'
                elif response[counter]['factorType']=='u2f':
                    factor='U2F Authentication'
                elif response[counter]['factorType']=='email':
                    factor='Email Authentication'
                elif response[counter]['factorType']=='token:software:totp' and response[counter]['provider']=='GOOGLE':
                    factor='Google Authenticator'
                elif response[counter]['factorType']=='token:hardware' and response[counter]['provider']=='YUBICO':
                    factor='Yubikey'
                elif response[counter]['factorType']=='web' and response[counter]['provider']=='DUO':
                    factor='DUO'
                else:
                    factor=response[counter]['factorType']

                userWriter.writerow([user["profile"]["firstName"], user["profile"]["lastName"], user["profile"]["email"], user["profile"]["login"], factor])
                counter+=1


if __name__ == "__main__":

	EnrolledUsers()
