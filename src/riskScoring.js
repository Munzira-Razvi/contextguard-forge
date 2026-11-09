const SENSITIVE_TERMS = [
  { match: 'auth', term: 'authentication' },
  { match: 'login', term: 'login' },
  { match: 'password', term: 'password' },
  { match: 'session', term: 'session' },
  { match: 'token', term: 'token' },
  { match: 'payment', term: 'payment' },
  { match: 'encrypt', term: 'encryption' },
];

export function detectSensitiveTopic(summary, labels = []) {
  const text = `${summary} ${labels.join(' ')}`.toLowerCase();
  return SENSITIVE_TERMS.find((t) => text.includes(t.match)) || null;
}

export function scoreRisk({ issue, linkedIssues, policyPages, sensitive }) {
  const factors = [];
  const add = (factor, points, detail) => factors.push({ factor, points, detail });

  if (sensitive) {
    add('Security-sensitive area', 25, `The issue concerns ${sensitive.term}.`);
  }

  const unresolved = linkedIssues.filter((l) => l.statusCategory !== 'done');
  if (unresolved.length > 0) {
    add(
      'Unresolved linked work',
      Math.min(30, unresolved.length * 15),
      `Open linked items: ${unresolved.map((l) => `${l.key} (${l.status})`).join(', ')}.`
    );
  }

  if (sensitive && policyPages.length > 0) {
    add(
      'Security policy applies',
      15,
      `Policy pages found: ${policyPages.map((p) => p.title).join(', ')}.`
    );
  }

  if (issue.statusCategory !== 'new' && unresolved.length > 0) {
    add(
      'Work ahead of review',
      20,
      `${issue.key} is ${issue.status} while a related item is still open.`
    );
  }

  if (sensitive && linkedIssues.length === 0) {
    add('No linked review', 10, 'No linked review work item was found.');
  }

  const score = Math.min(100, factors.reduce((sum, f) => sum + f.points, 0));
  const level = score >= 70 ? 'High attention' : score >= 40 ? 'Medium attention' : 'Low attention';

  return {
    score,
    level,
    factors,
    note: 'ContextGuard prioritization score from 0 to 100. This is not a CVSS score.',
  };
}