// OWASP A03:2021 - Injection
// Secure MongoDB / NoSQL query example

app.get('/user', async (req, res) => {
    try {

        const username = req.query.username;

        // Reject objects, arrays, or other unexpected types
        if (typeof username !== 'string') {
            return res.status(400).json({
                error: 'Invalid username'
            });
        }

        // Limit username size
        if (
            username.length < 1 ||
            username.length > 50
        ) {
            return res.status(400).json({
                error: 'Invalid username'
            });
        }

        // Only allow expected username characters
        const usernamePattern =
            /^[a-zA-Z0-9_.-]+$/;

        if (!usernamePattern.test(username)) {
            return res.status(400).json({
                error: 'Invalid username'
            });
        }

        const user =
            await db.collection('users').findOne(
                {
                    username: username
                },
                {
                    projection: {
                        password: 0,
                        passwordHash: 0
                    }
                }
            );

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