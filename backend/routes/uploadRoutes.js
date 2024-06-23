const express = require('express');
const router = express.Router();
const uploadController = require('../controllers/uploadController');

router.post('/logo', uploadController.uploadLogo);
router.delete('/logo/:filename', uploadController.deleteLogo);

module.exports = router;
