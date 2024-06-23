const express = require('express');
const router = express.Router();
const organizationController = require('../controllers/organizationController');
const authMiddleware = require('../middlewares/authMiddleware');

router.post('/', authMiddleware, organizationController.createOrganization);
router.get('/', authMiddleware, organizationController.getOrganizations);
router.get('/:id', authMiddleware, organizationController.getOrganizationById);
router.put('/:id', authMiddleware, organizationController.updateOrganization);
router.delete('/:id', authMiddleware, organizationController.deleteOrganization);

module.exports = router;
