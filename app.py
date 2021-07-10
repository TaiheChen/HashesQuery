from flask_sqlalchemy import SQLAlchemy
import time
import datetime
import os
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request
import requests

# api key: 28d7825c30ddf367f2ae5e3dc7bcba83a555a734f4fd42b7194a542d5d3fb78a

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'savedFiles/'  # initialize file upload function

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///example.db'  # initialize a database()
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# Vendor is the name of table, there are four attributes in the table
class Vendor(db.Model):
    Hash_value = db.Column(db.String, primary_key=True, unique=True, nullable=False)
    Fortinet_detection_name = db.Column(db.String, nullable=True)
    Number_of_engines_detected = db.Column(db.Integer, nullable=True)
    Scan_Date = db.Column(db.String, nullable=True)


# create a database
db.create_all()


# route the home page
@app.route('/')
def homepage():
    return 'Hello World!'


# route a file-upload page
@app.route('/upload')
def upload_file():
    return render_template('upload.html')


# POST the file upload request and calculate how long to get result
@app.route('/uploader', methods=['GET', 'POST'])
def uploader():
    # submit the file with POST request
    if request.method == 'POST':
        f = request.files['file']
        f.save(os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(f.filename)))

        # read the file and calculate how long to get result
        files = os.listdir('./savedFiles')
        f2 = open('./savedFiles/' + files[0], "r")
        # get how many pieces vendors need to query
        length = len(f2.readlines())
        # calculate how many days required for querying
        days = int(length / 500)
        length = length % 500
        # calculate how many hours required for querying
        hours = int(length / 240)
        # calculate how many minutes required for querying
        minutes = int((length % 240) / 4)
        return 'File uploaded successfully and the result will be available ' \
               'in ' + str(days) + ' days ' + str(hours) + ' hours ' + str(minutes) + ' minutes'
    # in case
    else:
        return render_template('upload.html')


# Route the report page
@app.route('/report')
def report():
    # store hashes as array in the uploaded file
    hashesArray = []
    files = os.listdir('./savedFiles')
    # get the first file in the savedFiles folder
    f2 = open('./savedFiles/' + files[0], "r")
    lines = f2.readlines()
    for hashes in lines:
        # append hashes to hashArray
        hashesArray.append(hashes.strip('\n'))
    # an array to store dictionary
    toHTML = []
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    # loop every hash value in the uploaded file
    for hashes in hashesArray:
        # Check if the hash value is in the database and scan date is not null
        if Vendor and Vendor.query.get(hashes) and Vendor.query.get(hashes).Scan_Date != "None":
            date = Vendor.query.get(hashes).Scan_Date
            #  convert date to formatted date as six digits
            formattedData = 100000 * int(float(date[2])) + 10000 * int(float(date[3])) + 1000 * int(
                float(date[5])) + 100 * int(
                float(date[6])) + 10 * int(float(date[8])) + int(float(date[9]))
            # Check if the scan date of the hash value within a day, if yes, we don't need to query with API
            if (int(datetime.date.today().strftime('%y%m%d')) - formattedData) < 2:
                #  Retrieve data from database and append them to the HTML file
                toHTML.append({"Hash_value": hashes,
                               "Fortinet_detection_name": Vendor.query.get(hashes).Fortinet_detection_name,
                               "Number_of_engines_detected": Vendor.query.get(hashes).Number_of_engines_detected,
                               "Scan_Date": Vendor.query.get(hashes).Scan_Date})
                # pass over next query, toHTML appending and database update/add operations.
                continue
        # Request data through calling API
        params = {'apikey': '28d7825c30ddf367f2ae5e3dc7bcba83a555a734f4fd42b7194a542d5d3fb78a', 'resource': hashes}
        # in case of minute maximum or daily maximum, it will sleep 60s
        while 99:
            response = requests.get(url, params=params)
            if response.status_code == 200:
                break
            time.sleep(60)
        response = response.json()
        # for some reason, the hash value is not acceptable
        if response['response_code'] != 1:
            toHTML.append({"Hash_value": hashes, "Fortinet_detection_name": "None", "Number_of_engines_detected": 0,
                           "Scan_Date": "None"})
        # everything's good and receive correct things
        else:
            scans = response['scans']
            fortinet = scans['Fortinet']
            toHTML.append({"Hash_value": hashes, "Fortinet_detection_name": fortinet['result'],
                           "Number_of_engines_detected": response['positives'], "Scan_Date": response['scan_date']})
        # Save data from toHTML array to database
        if Vendor and Vendor.query.get(hashes):
            # We just need update the database information since it's stored before
            Vendor.query.get(hashes).Fortinet_detection_name = toHTML[-1].get("Fortinet_detection_name")
            Vendor.query.get(hashes).Number_of_engines_detected = toHTML[-1].get("Number_of_engines_detected")
            Vendor.query.get(hashes).Scan_Date = toHTML[-1].get("Scan_Date")
        # If there is no data before, we will add a new piece of data to database
        else:
            db.session.add(Vendor(Hash_value=hashes, Fortinet_detection_name=toHTML[-1].get("Fortinet_detection_name"),
                                  Number_of_engines_detected=toHTML[-1].get("Number_of_engines_detected"),
                                  Scan_Date=toHTML[-1].get("Scan_Date"), ))
        # store to database
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()

    # Render the report page
    return render_template("report.html", toHTML=toHTML)

# Start the application
if __name__ == '__main__':
    app.run()
