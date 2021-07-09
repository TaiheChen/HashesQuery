from flask_sqlalchemy import SQLAlchemy
import time
import os
from werkzeug.utils import secure_filename
from flask import Flask, render_template, flash, request, redirect, url_for
from flask import request
import requests
import json
import types


# api key: 28d7825c30ddf367f2ae5e3dc7bcba83a555a734f4fd42b7194a542d5d3fb78a

# 1.calculate time
# 2，读取未知名字txt###########
# 3.在SQL存住
# 4.自动跳转

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'savedFiles/'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///example.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class Vendor(db.Model):
    Hash_value = db.Column(db.String, primary_key=True, unique=True, nullable=False)
    Fortinet_detection_name = db.Column(db.String, nullable=True)
    Number_of_engines_detected = db.Column(db.Integer, nullable=True)
    Scan_Date = db.Column(db.String, nullable=True)


db.create_all()


@app.route('/')
def homepage():
    return 'Hello World!'


@app.route('/upload')
def upload_file():
    return render_template('upload.html')


@app.route('/uploader', methods=['GET', 'POST'])
def uploader():
    if request.method == 'POST':
        f = request.files['file']
        print(request.files)
        f.save(os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(f.filename)))
        return 'file uploaded successfully'
    else:
        return render_template('upload.html')


@app.route('/report')
def report():
    hashesArray = []
    path = './savedFiles'
    files = os.listdir(path)
    f2 = open('./savedFiles/' + files[0], "r")
    lines = f2.readlines()
    for hashes in lines:
        hashesArray.append(hashes.strip('\n'))

    toHTML = []
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    for hashes in hashesArray:
        if toHTML and len(toHTML) % 4 == 0:
            print("Sleeping")
            time.sleep(60)
        params = {'apikey': '28d7825c30ddf367f2ae5e3dc7bcba83a555a734f4fd42b7194a542d5d3fb78a', 'resource': hashes}
        response = requests.get(url, params=params)
        # response = json.loads(response.content)
        response = response.json()
        print(response)
        print("\n")
        if response['response_code'] != 1:
            toHTML.append({"Hash_value": hashes, "Fortinet_detection_name": "None", "Number_of_engines_detected": 0,
                           "Scan_Date": "None"})
        else:
            scans = response['scans']
            fortinet = scans['Fortinet']
            toHTML.append({"Hash_value": hashes, "Fortinet_detection_name": fortinet['result'],
                           "Number_of_engines_detected": response['positives'], "Scan_Date": response['scan_date']})

    print(toHTML)
    return render_template("report.html", toHTML=toHTML)


if __name__ == '__main__':
    app.run()
