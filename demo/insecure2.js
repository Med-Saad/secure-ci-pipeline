// DEMO FIXTURE — intentionally insecure. Added by the PR head only, so the gate
// should treat finding B as NEW vs the merge base and BLOCK the pull request.
const express = require('express');
const app = express();
app.get('/b', (req, res) => {
  eval(req.query.cmd); // planted finding B (new on the PR head)
  res.send('ok');
});
