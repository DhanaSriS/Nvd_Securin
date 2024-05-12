const requestOptions = {
    method: "GET",
    redirect: "follow"
};

const batchSize = 2000;

const cvelist_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
const cvehistory_url = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"

const sortBy = (mode) => {
    switch ( mode ) {
        case '1':
            return {id: 1}
        case '2':
            return {id: -1}
        case '3':
            return {lastModified: 1}
        case '4':
            return {lastModified: -1}
        case '5':
            return {'metrics.cvssMetricV31[0].cvssData.baseScore': 1}
    }
}

module.exports = {requestOptions, batchSize, cvelist_url, cvehistory_url, sortBy}