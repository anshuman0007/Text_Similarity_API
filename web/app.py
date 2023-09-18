from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt
import spacy

app=Flask(__name__)
api=Api(app)

client=MongoClient("mongodb://db:27017")

db=client.SimilarityDB
users=db["Users"]
admin_collection=db['admins']

def UserExist(username):
    if users.count_documents({"Username":username})==0:
        return False
    else:
        return True

def AdminExists(adminuser):
    existing_admin=admin_collection.find_one()
    if admin_collection.count_documents({"AdminUser":adminuser})==0:
        return False
    elif existing_admin:
        retJson={
            "status":302,
            "msg":"Only 1 admin user allowed"
        }
        return jsonify(retJson)
    else:
        return True
    
class RegisterAdmin(Resource):
    def post(self):
        postedData=request.get_json()
        adminuser=postedData["adminuser"]
        adminpass=postedData["adminpass"] 

        if AdminExists(adminuser):
            retJson={
                "status":301,
                "msg":"Admin Already exists"
            }
            return jsonify(retJson)
              
        hashed_pw=bcrypt.hashpw(adminpass.encode('utf8'),bcrypt.gensalt())

        admin_collection.insert_one({
            "AdminUser":adminuser,
            "AdminPass":hashed_pw
        })

        retJson={
            "status":200,
            "msg": "Admin has been successfully Registered"
        }
        return jsonify(retJson)

class Register(Resource):
    def post(self):
        postedData=request.get_json()
        username=postedData["username"]
        password=postedData["password"]

        if UserExist(username):
            retJson={
                "status":301,
                "msg":"User Already Exists"
            }
            return jsonify(retJson)
        
        hashed_pw=bcrypt.hashpw(password.encode('utf8'),bcrypt.gensalt())

        users.insert_one({
            "Username": username,
            "Password": hashed_pw,
            "Tokens": 6
        })

        retJson={
            "status":200,
            "msg": "Congratulations, You have successfully signed off for the API"
        }

        return jsonify(retJson)

def verifyPw(username, password):
    if not UserExist(username):
        return False        

    hashed_pw =users.find({
        "Username":username
    })[0]["Password"]

    if bcrypt.hashpw(password.encode('utf8'),hashed_pw)==hashed_pw:
        return True
    else:
        return False

def verifyAdminPw(adminuser,adminpass):
    if not AdminExists(adminuser):
        return False
    hashed_pw=admin_collection.find({
        "AdminUser":adminuser
    })[0]["AdminPass"]

    if bcrypt.hashpw(adminpass.encode('utf8'),hashed_pw)==hashed_pw:
        return True
    else:
        return False

def countTokens(username):
    tokens= users.find({
        "Username":username
    })[0]["Tokens"]
    return tokens

class Detect(Resource):
    def post(self):
        postedData=request.get_json()

        username=postedData["username"]
        password=postedData["password"]
        text1=postedData["text1"]
        text2=postedData["text2"]

        if not UserExist(username):
            retJson={
                "status":301,
                "msg":"Invalid Username"
            }

            return jsonify(retJson)
        
        correct_pw=verifyPw(username, password)

        if not correct_pw:

            retJson={
                "status":302,
                "msg":"Invalid Password"
            }
            return jsonify(retJson)
        
        num_tokens=countTokens(username)

        if num_tokens<=0:
            retJson={
                "status": 303,
                "msg": "Sorry you are out of tokens, please refill!"
            }
            return jsonify(retJson)
    
        #Calculate the edit distance

        nlp=spacy.load('en_core_web_sm')
        text1= nlp(text1)
        text2=nlp(text2)

        #Ratio is a number beween 0 and 1 , closer to 1 the more similar text1 and text 2 are

        ratio=text1.similarity(text2)
        retJson={
            "status":200,
            "similarity":ratio,
            "msg":"Similarity score calculated successfully"
        }

        current_tokens=countTokens(username)

        users.update_one({
            "Username": username,
        },{
            "$set":{
            "Tokens": current_tokens-1
        }
        })
        return jsonify(retJson) 
    
class Refill(Resource):
    def post(self):
        postedData=request.get_json()
        adminuser=postedData["adminuser"]
        adminpass=postedData["adminpass"] 
        username=postedData["username"]
        refill_amount=postedData["refill"]

        if not AdminExists(adminuser):
            retJson={
                "status":301,
                "msg":"Invalid Admin Username"
            }

        correct_Adminpw=verifyAdminPw(adminuser, adminpass)

        if not correct_Adminpw:
                
            retJson={
                "status":304,
                "msg":"Invalid Admin Password"
            }
            return jsonify(retJson)
        
        if not UserExist(username):
            retJson={
                "status":301,
                "msg":"Invalid Username"
            }
            return jsonify(retJson)
        
        else:    
            users.update_one({
                "Username":username
            },{
                "$set":{
                "Tokens":refill_amount
            }
            })

            retJson={
                "status":200,
                "msg":"Tokens Refilled Successfully"
            }
            return jsonify(retJson)

api.add_resource(RegisterAdmin, '/adminregister')        
api.add_resource(Register,'/register')
api.add_resource(Detect,'/detect')
api.add_resource(Refill,'/refill') 

if __name__ == "__main__":
    app.run(host='0.0.0.0')
