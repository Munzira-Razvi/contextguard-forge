import api, { route } from '@forge/api';
import { detectSensitiveTopic, scoreRisk } from './riskScoring';

function readInput(args, name) {
  return args?.[name] ?? args?.payload?.[name];
}

async function getSiteOrigin() {
  try {
    const res = await api.asUser().requestJira(route`/rest/api/3/serverInfo`);
    if (!res.ok) return '';
    const info = await res.json();
    return new URL(info.baseUrl).origin;
  } catch (e) {
    return '';
  }
}

async function fetchIssue(issueKey) {
  const res = await api.asUser().requestJira(
    route`/rest/api/3/issue/${issueKey}?fields=summary,status,labels,issuelinks`
  );
  if (!res.ok) {
    return { error: `Could not read ${issueKey} (HTTP ${res.status}).` };
  }
  const issue = await res.json();
  const origin = await getSiteOrigin();
  const link = (key) => (origin ? `${origin}/browse/${key}` : undefined);

  const linkedIssues = (issue.fields.issuelinks || [])
    .map((l) => l.outwardIssue || l.inwardIssue)
    .filter(Boolean)
    .map((o) => ({
      key: o.key,
      summary: o.fields.summary,
      status: o.fields.status.name,
      statusCategory: o.fields.status.statusCategory?.key,
      url: link(o.key),
    }));

  return {
    key: issue.key,
    summary: issue.fields.summary,
    status: issue.fields.status.name,
    statusCategory: issue.fields.status.statusCategory?.key,
    labels: issue.fields.labels || [],
    url: link(issue.key),
    siteOrigin: origin,
    linkedIssues,
  };
}

async function searchConfluence(cql, origin) {
  const res = await api.asUser().requestConfluence(
    route`/wiki/rest/api/search?cql=${cql}&limit=5`
  );
  if (!res.ok) return { error: `Confluence search failed (HTTP ${res.status}).` };
  const data = await res.json();
  const base = data._links?.base || (origin ? `${origin}/wiki` : '');
  return {
    results: (data.results || []).map((r) => ({
      title: r.title,
      excerpt: r.excerpt,
      url: r.url ? (r.url.startsWith('http') ? r.url : `${base}${r.url}`) : undefined,
    })),
  };
}

async function findEvidence(topic, origin) {
  const safe = String(topic).replace(/["\\]/g, '');

  const labeled = await searchConfluence(
    `type = page AND label = "security-policy" AND text ~ "${safe}"`,
    origin
  );
  if (labeled.error) return labeled;
  if (labeled.results.length > 0) {
    return { source: 'labeled security-policy pages', results: labeled.results };
  }

  const general = await searchConfluence(`type = page AND text ~ "${safe}"`, origin);
  if (general.error) return general;
  return {
    source: 'general search; none of these are labeled security policies',
    results: general.results,
  };
}

export async function getIssueContext(args) {
  const issueKey = readInput(args, 'issueKey');
  if (!issueKey) return { error: 'No issue key was provided.' };
  return fetchIssue(issueKey);
}

export async function findSecurityEvidence(args) {
  const topic = readInput(args, 'topic');
  if (!topic) return { error: 'No topic was provided.' };
  return findEvidence(topic, '');
}

export async function analyzeContextualRisk(args) {
  const issueKey = readInput(args, 'issueKey');
  if (!issueKey) return { error: 'No issue key was provided.' };

  const issue = await fetchIssue(issueKey);
  if (issue.error) return issue;

  const sensitive = detectSensitiveTopic(issue.summary, issue.labels);
  let evidence = { source: 'not searched', results: [] };
  let evidenceError = null;

  if (sensitive) {
    const found = await findEvidence(sensitive.term, issue.siteOrigin);
    if (found.error) {
      evidenceError = found.error;
    } else {
      evidence = found;
    }
  }

  const policyPages =
    evidence.source === 'labeled security-policy pages' ? evidence.results : [];

  const risk = scoreRisk({
    issue,
    linkedIssues: issue.linkedIssues,
    policyPages,
    sensitive,
  });

  return { issue, evidence, evidenceError, risk };
}