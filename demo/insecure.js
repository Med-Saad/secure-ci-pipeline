// DEMO FIXTURE — intentionally insecure. Used to exercise the merge-base delta
// gate on a real pull_request. Never merged to main; see the delta-demo PR.
const express = require('express');
const app = express();
app.get('/a', (req, res) => {
  eval(req.query.cmd); // planted finding A (present on the PR base branch)
  res.send('ok');
});
