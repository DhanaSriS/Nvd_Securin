const express = require('express');
const mongoose = require('mongoose');

const nvdRouter = require('./route/cve-api-route');
const cveRouter = require('./route/view-route');
const Metadata = require('./models/cve-metadata');
const CVE = require('./models/cve-model');
const sleep = require('./module/sleep-module');
const { requestOptions, cvehistory_url, cvelist_url } = require ('./config/config');

require('dotenv').config();

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.use(express.static(__dirname + '/public'));

mongoose.connect('mongodb://localhost:27017/cve-database', {})
.then(() => {
    console.log('Connected to DB');
})
.catch((error) => {
    console.error('Error connecting to MongoDB:', error);
});

/*
app.listen(process.env.PORT, () => {
    console.log(`Server is running on port ${process.env.PORT}`);
});*/

app.get('/', (req, res) => {
    res.redirect('/cves/list?page=1&limit=10&sortMode=1')
});

app.use('/nvd', nvdRouter);
app.use('/cves', cveRouter);
const PORT = process.env.PORT || 3000; // Default port 3000 or a port specified in environment variable

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

setInterval(async () => {
    const metadata = await Metadata.findOne({ info: "Metadata" });
    await fetch(`${cvehistory_url}?resultsPerPage=1&startIndex=0`, requestOptions)
            .then((response) => response.json())
            .then((result) => { 
                if (result.totalResults !== metadata.cvehistory.total)   {
                    fetch(
                        `${cvehistory_url}?
                        resultsPerPage=${result.totalResults - metadata.cvehistory.total}&
                        startIndex=${metadata.cvehistory.total}`, 
                    requestOptions) 
                        .then((res) => res.json())
                        .then(async (result) => {
                            for(var j = 0; j < (result.totalResults - metadata.cvehistory.total); j++){
                                if (result.cveChanges[j].eventName !== "CVE Received") {
                                    await CVE.findOneAndDelete({ id: result.cveChanges[j].change.cveId })
                                }  
                                await fetch(`${cvelist_url}?cveId=${result.cveChanges[j].change.cveId}`, requestOptions)
                                    .then((res) => res.json())
                                    .then((result) => {
                                        CVE.create(result.vulnerabilities[0].cve).then((cve) => cve.save());
                                    })
                                await sleep(35000);
                            }
                        })
                        .then(() => {
                            console.log(`Updated DB with ${result.totalResults - metadata.cvehistory.total} records`)
                        })
                }
            })
    await fetch('http://localhost:3000/nvd/meta').then(() => {
        console.log("CVE Check Done")        
    });

}, 1000 * 60 * 30);