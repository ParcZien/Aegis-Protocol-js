import Aegis from './aegis.js';

function printResult(label, result) {
  console.log(`\n=== ${label} ===`);
  console.log(`status: ${result.status}`);

  if (result.status === 'VERIFIED') {
    console.log('sanitizedIntent:', result.sanitizedIntent);
    console.log('packet:', result.packet);
  } else {
    console.log('stage:', result.stage);
    console.log('code:', result.code);
    console.log('message:', result.message);
    console.log('details:', result.details);
  }
}

const manifest = {
  requiredKeys: ['action', 'target', 'amount'],
  ttlMs: 30000,
  safeIntegers: true,
  schema: {
    action: { type: 'string', whitelist: ['transfer', 'withdraw'] },
    target: { type: 'string', pattern: '^[a-zA-Z0-9@.]+$', maxLength: 100 },
    amount: { type: 'number', min: 0.01, max: 10000 }
  },
  contextRules: [
    { field: 'amount', operator: '<=', contextField: 'balance' },
    { field: 'action', operator: 'in', contextField: 'allowedActions' }
  ]
};

const context = {
  balance: 1000,
  allowedActions: ['transfer', 'withdraw']
};

const allowedProposal = {
  action: 'transfer',
  target: 'alice@bank.com',
  amount: 250
};

const deniedProposal = {
  action: 'transfer',
  target: 'alice@bank.com',
  amount: 50000
};

const allowedResult = await Aegis.verify(allowedProposal, manifest, context);
printResult('ALLOWED ACTION', allowedResult);

const deniedResult = await Aegis.verify(deniedProposal, manifest, context);
printResult('DENIED ACTION', deniedResult);
