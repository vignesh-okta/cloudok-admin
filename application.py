from flask import Flask,jsonify,request,render_template,redirect,url_for,send_file,Response, session
from flask_socketio import SocketIO, send
import eventlet, os 
eventlet.monkey_patch() 
# Python Scripts
import python.CreateUser,python.SearchUser,python.DeactivateUser,python.MFAEnrolled,python.Deleteuser
import json,requests,time, urllib.parse, jwt, configparser, core.Database
# SCIM Server ,
from core.cors import crossdomain
# from core.Database import Database
from core.RequireAuth import auth_required
from operations.Users import Users
from operations. Groups import Groups
from apscheduler.schedulers.background import BackgroundScheduler
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from base64 import b64decode

#SAML2
import logging
import uuid
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_bootstrap import Bootstrap
from saml2 import (
    BINDING_HTTP_POST,
    BINDING_HTTP_REDIRECT,
    entity,
)
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config
import requests

with open("data.txt", "r+") as f:
    metadata_url_for = json.loads(f.read().replace(',\n}',' \n}').replace('\n',' '))
    f.close()

file = open('./static/privatekey.pem','r')
external_key=file.read()
key = RSA.importKey(external_key)
cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
ops_users = Users()
ops_groups = Groups()
application = Flask(__name__)
application.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
socketio=SocketIO(application, cors_allowed_origins="*")
static_files = {
    '/static': './static',
}
def apialive():
    config = configparser.ConfigParser(allow_no_value=True)
    config.optionxform = str
    config.read('application.properties')
    for (key,value) in config.items('OrgConfig'):
        api_token = "SSWS "+ value
        headers = {'Accept':'application/json','Content-Type':'application/json','Authorization':api_token}
        url = "https://"+key+"/api/v1/users?limit=1"
        resp=requests.get(url, headers = headers)
        print(resp.json())
scheduler = BackgroundScheduler()
scheduler.add_job(apialive, trigger='interval', hours=360)
scheduler.start()
test=""
# @application.before_request
# def before_request():
    # print (request.endpoint)
    # print(request.cookies.get('session'))

@application.after_request
def add_header(response):
    response.cache_control.max_age = 0
    return response
@socketio.on('message')
def msg(mes):
    print("Message is:" + str(mes))
    send(str(mes),broadcast=True)
# ------------------------------  SAML --------------
Bootstrap(application)
application.secret_key =  "validated" # Replace with your secret key str(uuid.uuid4())
login_manager = LoginManager()
login_manager.setup_app(application)
logging.basicConfig(level=logging.DEBUG)
# NOTE:
#   This is implemented as a dictionary for DEMONSTRATION PURPOSES ONLY.
#   On a production system, this information must come
#   from your system's user store.
user_store = {}


def saml_client_for(idp_name=None):
    '''
    Given the name of an IdP, return a configuation.
    The configuration is a hash for use by saml2.config.Config
    '''

    if idp_name not in metadata_url_for:
        raise Exception("Settings for IDP '{}' not found".format(idp_name))
    acs_url = url_for(
        "idp_initiated",
        idp_name=idp_name,
        _external=True).replace('http://','https://')
    https_acs_url = url_for(
        "idp_initiated",
        idp_name=idp_name,
        _external=True,
        _scheme='https')

    #   SAML metadata changes very rarely. On a production system,
    #   this data should be cached as approprate for your production system.
    rv = requests.get(metadata_url_for[idp_name])

    settings = {
        'metadata': {
            'inline': [rv.text],
            },
        'service': {
            'sp': {
                'endpoints': {
                    'assertion_consumer_service': [
                        (acs_url, BINDING_HTTP_REDIRECT),
                        (acs_url, BINDING_HTTP_POST),
                        (https_acs_url, BINDING_HTTP_REDIRECT),
                        (https_acs_url, BINDING_HTTP_POST)
                    ],
                },
                # Don't verify that the incoming requests originate from us via
                # the built-in cache for authn request ids in pysaml2
                'allow_unsolicited': True,
                # Don't sign authn requests, since signed requests only make
                # sense in a situation where you control both the SP and IdP
                'authn_requests_signed': False,
                'logout_requests_signed': True,
                'want_assertions_signed': True,
                'want_response_signed': False,
            },
        },
    }
    spConfig = Saml2Config()
    spConfig.load(settings)
    spConfig.allow_unknown_attributes = True
    saml_client = Saml2Client(config=spConfig)
    return saml_client


class User(UserMixin):
    def __init__(self, user_id):
        user = {}
        self.uname=user_id
        self.id = None
        self.first_name = None
        self.last_name = None
        try:
            user = user_store[user_id]
            self.id = unicode(user_id)
            self.first_name = user['first_name']
            self.last_name = user['last_name']
        except:
            pass


@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

@application.route("/get",methods=['POST'])
@login_required
def get_url():
    ep = request.form.get('data')
    url=metadata_url_for[ep]
    return requests.get(url).text

@application.route("/set",methods=['POST'])
@login_required
def set_metadata():
    ep = request.form.get('data')
    with open("idp.txt", 'w') as f:
        f.write(ep)
        f.close()
    return "success", 200

@application.route("/setidp",methods=['POST'])
@login_required
def set_idp():
    idp = request.form.get('idp')
    url = request.form.get('url')
    insert_string="\""+idp+"\""+':'+"\""+url+"\",\n"
    with open('data.txt', 'r+') as fd:
        contents = fd.readlines()
        if '{' in contents[-1]:  # Handle last line to prevent IndexError
            contents.append(insert_string)
        else:
            for index, line in enumerate(contents):
                if '{' in line and insert_string not in contents[index + 1]:
                    contents.insert(index + 1, insert_string)
                    break
        fd.seek(0)
        fd.writelines(contents)

    return "success", 200

@application.route("/delidp",methods=['POST'])
@login_required
def delidp():
    idp = request.form.get('idp')
    with open("data.txt", "r+") as f:
        d = f.readlines()
        f.seek(0)
        for i in d:
            if idp not in i:
                f.write(i)
        f.truncate()
    return "success", 200

@application.route("/impersonate")
@login_required
def impersonate():
    return render_template('impersonate.html')

@application.route("/saml")
def main_page():
    with open("data.txt", "r+") as f:
        global metadata_url_for
        metadata_url_for = json.loads(f.read().replace(',\n}',' \n}').replace('\n',' '))
        default_idp=open("idp.txt", "r+").read()
        f.close()
    return render_template('main_page.html', idp_dict=metadata_url_for, default_idp=default_idp)

@application.route("/login/auth", methods=['POST'])
def login_auth():
    data=request.form.get('data')
    print(data)
    idToken=jwt.decode(data, verify=False)
    print(idToken['preferred_username'])
    session['username']=idToken['preferred_username']
    user = User(idToken['preferred_username'])
    print(session['username'])
    login_user(user)
    return 'Login Successul',200

@application.route("/saml/sso/<idp_name>", methods=['POST'])
def idp_initiated(idp_name):
    saml_client = saml_client_for(idp_name)
    authn_response = saml_client.parse_authn_request_response(
        request.form['SAMLResponse'],
        entity.BINDING_HTTP_POST)
    print(authn_response)
    authn_response.get_identity()
    user_info = authn_response.get_subject()
    print("User")
    print(authn_response.ava)
    username = user_info.text
    session['username']=username

    # This is what as known as "Just In Time (JIT) provisioning".
    # What that means is that, if a user in a SAML assertion
    # isn't in the user store, we create that user first, then log them in
    if username not in user_store:
        user_store[username] = {
            'first_name': authn_response.ava['FirstName'][0],
            'last_name': authn_response.ava['LastName'][0],
            }
    user = User(username)
    session['saml_attributes'] = authn_response.ava
    print("-->")
    print(vars(user))
    print(vars(session))
    login_user(user)
    url = url_for('user1')
    # NOTE:
    #   On a production system, the RelayState MUST be checked
    #   to make sure it doesn't contain dangerous URLs!
    if 'RelayState' in request.form:
        url = request.form['RelayState']
    return redirect(url)


@application.route("/saml/login/<idp_name>")
def sp_initiated(idp_name):
    RelayState='/dashboard'
    with open("idp.txt", "r+") as f:
        idp=f.read().replace('\n','')
        print(idp)
        f.close()
    saml_client = saml_client_for(idp)
    reqid, info = saml_client.prepare_for_authenticate(relay_state=RelayState)

    redirect_url = None
    # Select the IdP URL to send the AuthN request to
    for key, value in info['headers']:
        if key == 'Location':
            redirect_url = value
    response = redirect(redirect_url, code=302)
    # NOTE:
    #   I realize I _technically_ don't need to set Cache-Control or Pragma:
    #     http://stackoverflow.com/a/5494469
    #   However, Section 3.2.3.2 of the SAML spec suggests they are set:
    #     http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf
    #   We set those headers here as a "belt and suspenders" approach,
    #   since enterprise environments don't always conform to RFCs
    response.headers['Cache-Control'] = 'no-cache, no-store'
    response.headers['Pragma'] = 'no-cache'
    return response


@application.route("/user1")
@login_required
def user1():
    return render_template('index.html', session=session)


@application.errorhandler(401)
def error_unauthorized(error):
    return redirect(url_for('login'))


@application.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))
# ------------------------------
@application.route('/regreq')
@login_required
def regreq():
    if core.Database.mydb.is_connected()==False:
        core.Database.mydb.reconnect()
    req=ops_users.get_regs()
    data = {
        'data': req
        }
    return json.dumps(data)

@application.route('/.well-known/acme-challenge/<challenge>')
def letsencrypt_check(challenge):
    challenge_response = {
        "<challenge_token>":"<challenge_response>"
    }
    return Response(challenge_response[challenge], mimetype='text/plain')
@application.route('/register',methods=['GET','POST','PUT','DELETE'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    elif request.method == 'POST':
        # print("Args:"+request.args.get('data'))
        print("Form:"+request.form.get('data'))
        data=json.loads(request.form.get('data'))
        req_url = request.base_url
        ops_users.reg_user(data["firstName"],data["lastName"],data["password"],data["email"],req_url)
        # data["password"] = cipher.decrypt(b64decode(data["password"])).decode("utf-8")
        # print(data)
        # url="https://vigneshl.okta.com/api/v1/registration/reg2409dq4m1Ow9cd2p7/register"
        # headers = {'Accept':'application/json','Content-Type':'application/json'}
        # data1 = '{"userProfile":'+json.dumps(data)+'}'
        # print(data1)
        # response = requests.post(url, data = data1, headers = headers)
        # responseJSON = response.json()
        # if (response.status_code) == 200:
        #     print(responseJSON["activationToken"])
        # elif (response.status_code) == 400:
        #     print(responseJSON['errorCauses'][0]['errorSummary'])
        return 'success', 200, {'ContentType':'application/json'}

@application.route('/reg',methods=['PUT','DELETE'])
def reg():
    data  = request.form.get('data').split(',')
    config = configparser.ConfigParser(allow_no_value=True)
    config.optionxform = str
    config.read('application.properties')
    if request.method == 'PUT':
        print(data)
        password = cipher.decrypt(b64decode(data[3])).decode("utf-8")
        url="https://vigneshl.okta.com/api/v1/users"
        api_token = "SSWS "+ config['OrgConfig']["vigneshl.okta.com"]
        headers = {'Accept':'application/json','Content-Type':'application/json','Authorization':api_token}
        data1='{"profile":{"firstName":"'+data[1]+'","lastName":"'+ data[2]+'","email":"'+data[4]+'","login":"'+data[4]+'"},"credentials": {"password" : { "value":"'+password+'"}}}'
        print(data1)
        response = requests.post(url, data = data1, headers = headers)
        responseJSON = response.json()
        if (response.status_code) == 200:
            print(responseJSON)
            req_url = request.base_url
            ops_users.del_user(data[0])
            return json.dumps({'success':True}), 200, {'ContentType':'application/json'}

        elif (response.status_code) == 400:
            print(responseJSON['errorCauses'][0]['errorSummary'])
            return json.dumps(responseJSON['errorCauses'][0]['errorSummary']), 400, {'ContentType':'application/json'}


    elif request.method == 'DELETE':
        req_url = request.base_url
        ops_users.del_user(data[0])
        return json.dumps({'success':True}), 200, {'ContentType':'application/json'}

@application.route('/')
def login():
    return render_template('sign-in.html')

@application.route('/forgot-password')
def forgot_password():
    return render_template('forgot-password.html')
#rendering the HTML page which has the button
@application.route('/dashboard')
# @login_required
def dashboard():
    return render_template('index.html')
@application.route('/scripts')
# @login_required
def scripts():
    return render_template('base.html')
@application.route('/hook',methods=['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH'])
def hook():
    global test
    # if request.method =='POST':

    req_url = request.base_url
    ops_users.create_req(request.data,request.method,str(request.headers),request.access_route[-1],request.endpoint,req_url)
    if request.data:
        socketio.emit('message', {"data": json.loads(request.data), "req": request.method, "header": str(request.headers), "ip": request.access_route[-1], "endpoint": request.endpoint})
        if 'x-okta-verification-challenge' in request.headers:
            return '{"verification" : "' + request.headers.get('x-okta-verification-challenge') +'"}'

        elif request.headers.get('User-Agent') == 'Okta-Integrations' and json.loads(request.data)['eventType']=='com.okta.user.pre-registration':
            return '{"commands":[{"type":"com.okta.action.update","value":{"registration":"DENY"}}]}'

        elif request.headers.get('User-Agent') == 'Okta-Integrations' and json.loads(request.data)['eventType']=='com.okta.user.credential.password.import':
            return '{"commands":[{"type":"com.okta.action.update","value":{"credential":"VERIFIED"}}]}'

        else :
            test = request.data
            return test

    else:
        socketio.emit('message', {"data": {}, "req": request.method, "header": str(request.headers), "ip": request.access_route[-1], "endpoint": request.endpoint})
        if 'x-okta-verification-challenge' in request.headers:
            return '{"verification" : "' + request.headers.get('x-okta-verification-challenge') +'"}'
        else :
            return json.dumps({'success':True}), 200, {'ContentType':'application/json'}
    # if request.method =='GET':
    #     print(json.loads(test))
    #     if test:
    #         return test
    #     else:
    #         return jsonify(test='Loading')

@application.route('/ihook',methods=['GET','DELETE'])
@login_required
def ihook():
    if core.Database.mydb.is_connected()==False:
        core.Database.mydb.reconnect()
    req=ops_users.get_req()
    data = {
        'data': req
        }
    if request.method =='GET':
        if req:
            return render_template('webhook.html',req=data)
        else:
            return render_template('webhook.html',req="")
    if request.method =='DELETE':
        clear()
        return json.dumps({'success':True}), 200, {'ContentType':'application/json'}
def clear():
    core.Database.mycursor.execute("DELETE from `Socket`")

@application.route('/oidc')
@login_required
def oidc():
    return render_template('oidc.html')
@application.route('/oauth2', methods=['GET','POST'])
def oauth():
    if len(request.args) != 0:
        code=request.args.get('code')
        state=request.args.get('state')
    elif len(request.form) != 0:
        code=request.form.get('code')
        state=request.form.get('state')
    try:
        return render_template('oauth.html', code = code)
    except:
        return render_template("oidc.html")
@application.route('/token', methods=['GET','POST'])
@login_required
def token():
    if request.method =='GET':
        return render_template("oidc.html")
    else:
        if request.form.get('url'):
            authurl=request.form.get('url')+'/token'
        else:
            authurl="https://login.vigneshl.com/oauth2/ausb5g9kv7Zx8BGxX2p7/v1/token"
        headers = {'Content-Type':'application/x-www-form-urlencoded'}
        body = "client_id="+request.form.get('clientid')+"&client_secret=MgYM6yiyb2Q5oy4CeaFXFxH7Skg-nwOpjDLcs7b4&grant_type=authorization_code&redirect_uri="+urllib.parse.quote_plus(request.form.get('redirect_uri'))+"&code="+request.form.get('code')
        print(body)
        resp=requests.post(authurl, data=body, headers=headers)
        print(resp)
        if "error" in resp.json():
            return render_template("oidc.html")
        else:
            atok=jwt.decode(resp.json()['access_token'], verify=False)
            idtok=jwt.decode(resp.json()['id_token'], verify=False)
        try:
            return render_template('token.html',idtok =idtok,atok = atok )
        except:
            return render_template("oidc.html")
@application.route('/approve')
@login_required
def approve():
    if core.Database.mydb.is_connected()==False:
        core.Database.mydb.reconnect()
    req=ops_users.get_regs()
    data = {
        'data': req
        }
    return render_template('approval.html',data=data)

@application.route('/update', methods=['POST'])
@login_required
def update():
    uname  = request.form.get('uname')
    org = request.form.get('org')
    config = configparser.ConfigParser(allow_no_value=True)
    config.optionxform = str
    config.read('application.properties')
    url="https://"+org+"/api/v1/users/"+session['username']
    api_token = "SSWS "+ config['OrgConfig'][org]
    headers = {'Accept':'application/json','Content-Type':'application/json','Authorization':api_token}
    data1='{"profile":{"imp_username":"'+uname+'"}}'
    response = requests.post(url, data = data1, headers = headers)
    responseJSON = response.json()
    if (response.status_code) == 200:
        print(responseJSON)
    #     req_url = request.base_url
    #     ops_users.del_user(data[0])
        return json.dumps({'success':True}), 200, {'ContentType':'application/json'}
    #
    elif (response.status_code) == 400:
    #     print(responseJSON['errorCauses'][0]['errorSummary'])
        return json.dumps(responseJSON['errorCauses'][0]['errorSummary']), 400, {'ContentType':'application/json'}

@application.route('/delete_user')
@login_required
def delete_user():
    org =request.args.get('org')
    response = python.Deleteuser.DeleteUsers(str(org))
    return json.dumps(response)
@application.route('/create_user', methods=['GET','POST'])
@login_required
def create_user():
    if len(request.args) == 0:
        return "Error: Not Allowed"
    N=request.args.get('N')
    M=request.args.get('M')
    fn=request.args.get('fn')
    ln=request.args.get('ln')
    dn=request.args.get('dn')
    org =request.args.get('org')
    print ("N="+ str(N))
    print("M=" + str(M))
    response = python.CreateUser.CreateUsers(int(N),int(M),str(fn),str(ln),str(dn),str(org))
    return json.dumps(response)
@application.route('/search_user')
@login_required
def search_user():
    srch_qry=request.args.get('query')
    list=request.args.get('ulist')
    filter=request.args.get('filter')
    con=request.args.get('con')
    org =request.args.get('org')
    response = python.SearchUser.SearchUsers(str(srch_qry),str(list),str(filter),str(con),str(org))
    print(response)
    return json.dumps(response)
@application.route('/deactivate_user')
@login_required
def deactivate_user():
    user_list=request.args.get('userlist')
    org =request.args.get('org')
    response = python.DeactivateUser.DeactivateUsers(str(user_list),str(org))
    return json.dumps(response)
@application.route('/hooks', methods = ['GET','POST'])
def hooks():
    if 'x-okta-verification-challenge' in request.headers:
        return '{"verification" : "' + request.headers.get('x-okta-verification-challenge') +'"}'
    else:
        data=(json.loads(request.data))
        requests.post('https://webhook.site/fe04fc90-7249-4e9c-b934-85badf6dff1f', json=data)
        # print (data['data'])
        moddata=json.loads('{"eventType":"'+str(data['data']['events'][0]['eventType'])+'","displayMessage":"'+str(data['data']['events'][0]['displayMessage'])+'","userAgent":'+json.dumps(data['data']['events'][0]['client']['userAgent'])+',"ipAddress":"'+str(data['data']['events'][0]['client']['ipAddress'])+'","actor":'+json.dumps(data['data']['events'][0]['actor'])+',"outcome":'+json.dumps(data['data']['events'][0]['outcome'])+'}')
        requests.post('https://webhook.site/fe04fc90-7249-4e9c-b934-85badf6dff1f', json=moddata)
        # print(data['data']['user']['profile']['login'])
        # return hookfunc(data['data']['appUser']['profile']['userName'])
        return '', 200
# def modhook(data):
#
#     return 0
# def hookfunc(uname):
#     username=CheckUser.CheckUser(uname)
#     responsedata={"commands": [{ "type":"com.okta.user.profile.update", "value":{ "login":username}},{"type": "com.okta.action.update", "value": { "result": "CREATE_USER" } }]}
#     requests.post('https://webhook.site/fe04fc90-7249-4e9c-b934-85badf6dff1f', json=responsedata)
#     return jsonify(responsedata)
        # return 'Response Code 200'
@application.route('/enrollreport')
@login_required
def enrollreport():
    org =request.args.get('org')
    python.MFAEnrolled.EnrolledUsers(str(org))
    return send_file('./static/Enrolled-Users.csv',as_attachment=True, attachment_filename='MFA_Enrollment_report.csv')
@application.route('/sample')
def sample():
    return render_template('test.html')
@application.route ("/scim/v2/ServiceProviderConfigs")
def config():
    return jsonify({ "schemas": [   "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig" ], "patch": {   "supported": "true"  },  "bulk": {  "supported": "false",   "maxOperations": 0,   "maxPayloadSize": 0  },  "filter": {    "supported": "true",    "maxResults": 500  },  "changePassword": {    "supported": "true"  },  "sort": {    "supported": "false"  },  "etag": {    "supported": "false"  },  "urn:okta:schemas:scim:providerconfig:1.0": {"userManagementCapabilities": ["GROUP_PUSH", "IMPORT_NEW_USERS", "IMPORT_PROFILE_UPDATES", "PUSH_NEW_USERS", "PUSH_PASSWORD_UPDATES", "PUSH_PENDING_USERS", "PUSH_PROFILE_UPDATES", "PUSH_USER_DEACTIVATION", "REACTIVATE_USERS" ] },  "meta": {    "resourceType": "ServiceProviderConfig",    "location": "https://example.com/scim/v2/ServiceProviderConfig"  }})
@application.route("/scim/users")
@crossdomain(origin='*')
def users():
    req_url = request.base_url
    usr = ops_users.get_all_users(req_url, 1, 100)
    usr_all= usr["Resources"]
    i = 0
    all_users = []
    profileUrls = []
    while i < len(usr_all):
        userName = usr_all[i]["userName"]
        profileUrl = usr_all[i]["profileUrl"]
        all_users.append(userName)
        profileUrls.append(profileUrl)
        i += 1
    zip_users = zip(all_users, profileUrls)
    users = dict(zip_users)
    return render_template("index.html",users=users, title="All Users")
@application.route("/scim/users/<string:userId>")
@crossdomain(origin='*')
def user(userId):
    req_url = request.base_url
    usr = ops_users.get_user(userId, req_url)
    userName = usr["userName"]
    firstName = usr["name"]["givenName"]
    return render_template("profile.html",userName=userName, firstName=firstName, title=firstName)
@application.route("/scim/v2", methods = ['GET', 'OPTIONS'])
@crossdomain(origin='*')
# @auth_required(method='oauth2')
def default_scim_route():
    response = application.response_class(
    response = "<h1>Hello World</h1>",
    status = 200,
    mimetype='text/html'
    )
    return response
@application.route("/scim/v2/Users", methods = ['GET', 'POST', 'OPTIONS'])
@crossdomain(origin='*')
# @auth_required(method='oauth2')
def users_route():
    req_url = request.base_url
    if request.method == 'GET':
        filters = ["userName", "givenName", "middleName", "familyName", "email"]
        start_index = request.args.get("startIndex")
        count =  request.args.get("count")
        if not start_index:
            start_index = 1
        if not count:
            count = 100
        f = request.args.get("filter")
        if f:
            f = urllib.parse.unquote(f)
            i = 0
            while i < len(f):
                if filters[i] in f:
                    attribute_name = filters[i]
                    break
                i += 1
            #f - filter found in URL,  a - attributeName, e - end[index position] of string attributeName, t - total length of the filter string.
            a = attribute_name
            e = len(a)
            t = len(f)
            attribute_value = f[e:t].replace(' eq ', "").replace('"', "")
            filtered_users = ops_users.get_filtered_users(req_url, attribute_name, attribute_value, start_index, count)
            try:
                if filtered_users['status']:
                    http_code = filtered_users['status']
            except KeyError:
                    http_code = 200
                    pass
            response = application.response_class(
                response = json.dumps(filtered_users),
                status = http_code,
                mimetype='application/scim+json'
            )
            return response
        else:
            all_groups = ops_users.get_all_users(req_url, start_index, count)
            try:
                if all_groups['status']:
                    http_code = all_groups['status']
            except KeyError:
                http_code = 200
                pass
            response = application.response_class(
                response = json.dumps(all_groups),
                status = http_code,
                mimetype='application/scim+json'
            )
            return response
    elif request.method == 'POST':
        data = request.data
        user_data_json = json.loads(data)
        new_user = ops_users.create_user(user_data_json, req_url)
        try:
            if new_user['status']:
                http_code = new_user['status']
        except KeyError:
            http_code = 201
        response = application.response_class(
            response = json.dumps(new_user),
            status = http_code,
            mimetype='application/scim+json'
        )
        return response
@application.route("/scim/v2/Users/<string:id>", methods = ['GET', 'PUT', 'PATCH'])
@crossdomain(origin='*')
# @auth_required(method='oauth2')
def users_by_id_route(id):
    id = str(id)
    req_url = request.base_url
    if request.method == 'GET':
        get_user = ops_users.get_user(id, req_url)
        try:
            if get_user['status']:
                http_code = get_user['status']
        except KeyError:
                http_code = 200
                pass
        response = application.response_class(
            response = json.dumps(get_user),
            status = http_code,
            mimetype='application/scim+json'
        )
        return response
    elif request.method == 'PUT':
        data = request.data
        user_data_json = json.loads(data)
        update_user = ops_users.update_user(user_data_json, id, req_url)
        try:
            if update_user['status']:
                http_code = update_user['status']
        except KeyError:
            http_code = 200
        response = application.response_class(
            response = json.dumps(update_user),
            status = http_code,
            mimetype='application/scim+json'
        )
        return response
    elif request.method == 'PATCH':
        data = request.data
        user_data_json = json.loads(data)
        patch_user = ops_users.patch_user(user_data_json, id, req_url)
        try:
            if patch_user['status']:
                http_code = patch_user['status']
        except KeyError:
            http_code = 202
        response = application.response_class(
            response = json.dumps(patch_user),
            status = http_code,
            mimetype = 'application/scim+json'
        )
        return response
@application.route("/scim/v2/Groups", methods = ['GET', 'POST', 'OPTIONS'])
@crossdomain(origin='*')
# @auth_required(method='oauth2')
def groups_route():
    req_url = request.base_url
    if request.method == "GET" :
        start_index = request.args.get("startIndex")
        count =  request.args.get("count")
        filters = ["displayName"]
        if not start_index:
            start_index = 1
        if not count:
            count = 100
        f = request.args.get("filter")
        if f:
            f = urllib.parse.unquote(f)
            i = 0
            while i < len(f):
                if filters[i] in f:
                    attribute_name = filters[i]
                    break
                i += 1
            #f - filter found in URL,  a - attributeName, e - end[index position] of string attributeName, t - total length of the filter string.
            a = attribute_name
            e = len(a)
            t = len(f)
            attribute_value = f[e:t].replace(' eq ', "").replace('"', "")
            filtered_groups = ops_groups.get_filtered_groups(attribute_name, attribute_value, req_url, start_index, count)
            try:
                if filtered_groups['status']:
                    http_code = filtered_groups['status']
            except KeyError:
                    http_code = 200
                    pass
            response = application.response_class(
                response = json.dumps(filtered_groups),
                status = http_code,
                mimetype='application/scim+json'
            )
            return response
        else:
            all_groups = ops_groups.get_all_groups(req_url, start_index, count)
            try:
                if all_groups['status']:
                    http_code = all_groups['status']
            except KeyError:
                http_code = 200
                pass
            response = application.response_class(
                response = json.dumps(all_groups),
                status = http_code,
                mimetype='application/scim+json'
            )
            return response
    elif request.method == 'POST':
        data = request.data
        group_data_json = json.loads(data)
        new_group = ops_groups.create_group(group_data_json, req_url)
        try:
            if new_group['status']:
                http_code = new_group['status']
        except KeyError:
            http_code = 201
        response = application.response_class(
            response = json.dumps(new_group),
            status = http_code,
            mimetype='application/scim+json'
        )
        return response
@application.route("/scim/v2/Groups/<string:id>", methods = ['GET', 'PUT', 'PATCH', 'DELETE'])
@crossdomain(origin='*')
# @auth_required(method='oauth2')
def groups_by_id_route(id):
    id = str(id)
    req_url = request.base_url
    if request.method == "GET":
        get_group = ops_groups.get_group(id, req_url)
        try:
            if get_group['status']:
                http_code = get_group['status']
        except KeyError:
                http_code = 200
                pass
        response = application.response_class(
            response = json.dumps(get_group),
            status = http_code,
            mimetype='application/scim+json'
        )
        return response
    if request.method == "PUT":
        response = application.response_class(
            response = "<h1>Hello World</h1>",
            status = 200,
            mimetype='text/html'
            )
        return response
    if request.method == "PATCH":
        data = request.data
        group_data_json = json.loads(data)
        patch_group = ops_groups.patch_group(group_data_json, id, req_url)
        try:
            if patch_group["status"]:
                http_code = patch_group["status"]
        except KeyError:
            http_code = 202
        response = application.response_class(
            response = json.dumps(patch_group),
            status = http_code,
            mimetype = "application/scim+json"
        )
        return response
    if request.method == "DELETE":
        delete_group = ops_groups.delete_group(id, req_url)
        response = application.response_class(
            response = '',
            status = 204,
            mimetype = "application/scim+json"
        )
        return response
if __name__ == '__main__':
    socketio.run(application,debug="true", host="0.0.0.0", port=os.environ['PORT'])
    # application.run(host="0.0.0.0",debug="true")
    #application.run(host='192.168.1.79',debug=True, port=443,ssl_context=('cert.pem','pkey.pem'))
