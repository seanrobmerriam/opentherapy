
const express = require('express');
const { authenticateToken, authorizeRoles, authorizePermissions } = require('./middleware/auth');

const app = express();

// Public route
app.get('/api/public', (req, res) => {
  res.json({ message: 'This is a public endpoint' });
});

// Protected route - requires authentication
app.get('/api/protected', authenticateToken, (req, res) => {
  res.json({ 
    message: 'This is a protected endpoint',
    user: req.user 
  });
});

// Admin only route
app.get('/api/admin', authenticateToken, authorizeRoles('admin'), (req, res) => {
  res.json({ message: 'Admin access granted' });
});

// Multiple roles allowed
app.get('/api/staff', authenticateToken, authorizeRoles('admin', 'moderator'), (req, res) => {
  res.json({ message: 'Staff access granted' });
});

// Permission-based access
app.delete('/api/posts/:id', authenticateToken, authorizePermissions('delete'), (req, res) => {
  res.json({ message: 'Delete permission granted' });
});

// Multiple permissions (user needs at least one)
app.post('/api/content', authenticateToken, authorizePermissions('write', 'manage_users'), (req, res) => {
  res.json({ message: 'Content creation allowed' });
});
*/
