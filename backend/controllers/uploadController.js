const path = require('path');
const fs = require('fs');

exports.uploadLogo = (req, res) => {
    if (!req.files || Object.keys(req.files).length === 0) {
        return res.status(400).send('No files were uploaded.');
    }

    const logo = req.files.logo;
    const uploadPath = path.join(__dirname, '..', 'uploads', 'logos', logo.name);

    logo.mv(uploadPath, function (err) {
        if (err) {
            return res.status(500).send(err);
        }

        res.status(200).send({ message: 'File uploaded!', filename: logo.name });
    });
};

exports.deleteLogo = (req, res) => {
    const { filename } = req.params;
    const filePath = path.join(__dirname, '..', 'uploads', 'logos', filename);

    fs.unlink(filePath, err => {
        if (err) {
            return res.status(500).send(err);
        }

        res.status(200).send({ message: 'File deleted!' });
    });
};
