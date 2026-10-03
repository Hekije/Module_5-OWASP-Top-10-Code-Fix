// OWASP A01:2021 - Broken Access Control
// Secure version

app.get('/profile/:userId', requireAuth, async (req, res) => {
    try {
        const requestedUserId = req.params.userId;

        // Users can only access their own profile.
        // Administrators may access other profiles.
        if (
            requestedUserId !== req.user.id.toString() &&
            req.user.role !== 'admin'
        ) {
            return res.status(403).json({
                error: 'Access denied'
            });
        }

        const user = await User.findById(requestedUserId)
            .select('-password -passwordHash');

        if (!user) {
            return res.status(404).json({
                error: 'User not found'
            });
        }

        res.json(user);

    } catch (error) {
        res.status(500).json({
            error: 'Internal server error'
        });
    }
});
