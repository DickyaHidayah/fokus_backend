const express = require('express');
const router = express.Router();
const volunteerController = require('../controllers/volunteerController');
const authMiddleware = require('../middlewares/authMiddleware');

router.post('/', authMiddleware, volunteerController.createVolunteerProfile);
router.get('/', volunteerController.getVolunteers);
router.get('/:id', volunteerController.getVolunteerById);
router.put('/:id', authMiddleware, volunteerController.updateVolunteerProfile);
router.delete('/:id', authMiddleware, volunteerController.deleteVolunteerProfile);

module.exports = router;
