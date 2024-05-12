const router = require('express').Router();
const cveMetadata = require('../models/cve-metadata');

const CVE = require('../models/cve-model');
const { sortBy } = require('../config/config');
const sleep = require('../models/sleep-module');

router.get('/list', async (req, res) => {
  var total = 0;
  const aggregateOptions = [
    {$sort: sortBy(req.query.sortMode)},
    {$skip: (parseInt(req.query.page) - 1) * parseInt(req.query.limit)},
    {$limit: parseInt(req.query.limit)}
  ];
  if (req.query.search !== '' && req.query.search) {
    aggregateOptions.unshift({$match: {'id': {$regex: req.query.search}}})
    total = await CVE.countDocuments({'id': {$regex: req.query.search}})
  } else {
    const meta = await cveMetadata.findOne({ info: "Metadata" });
    total = meta.cve.total;
  }
  const cve = await CVE.aggregate(aggregateOptions)

  res.render('cvelist', {
    data : cve, 
    page: req.query.page, 
    limit: req.query.limit, 
    sortmode: req.query.sortMode, 
    totalRecords: total, 
    search: req.query.search ? req.query.search : undefined
  });
});

router.get('/:cveId', async (req, res) => {
  CVE.findOne({id: req.params.cveId}).then((cve) =>{
    if(cve.vulnStatus == 'Rejected') {
      res.redirect('/cves/' + cve.descriptions[0].value.split(' ')[cve.descriptions[0].value.split(' ').indexOf("ConsultIDs:") + 1].replace('.', ''));
    }
    res.render('cvedetail', {data: cve});
  });
});

module.exports = router;