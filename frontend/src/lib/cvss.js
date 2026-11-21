const METRICS = {
  AV: { name: 'Attack vector', values: { N: 'Network', A: 'Adjacent network', L: 'Local', P: 'Physical' } },
  AC: { name: 'Attack complexity', values: { L: 'Low', H: 'High' } },
  PR: { name: 'Privileges required', values: { N: 'None', L: 'Low', H: 'High' } },
  UI: { name: 'User interaction', values: { N: 'None', R: 'Required' } },
  S: { name: 'Scope', values: { U: 'Unchanged', C: 'Changed' } },
  C: { name: 'Confidentiality impact', values: { N: 'None', L: 'Low', H: 'High' } },
  I: { name: 'Integrity impact', values: { N: 'None', L: 'Low', H: 'High' } },
  A: { name: 'Availability impact', values: { N: 'None', L: 'Low', H: 'High' } },
}

export function describeVector(vector) {
  return vector
    .split('/')
    .slice(1)
    .map((part) => {
      const [key, value] = part.split(':')
      const meta = METRICS[key]
      return meta ? { key, name: meta.name, value: meta.values[value] ?? value } : null
    })
    .filter(Boolean)
}

export function calculatorUrl(vector) {
  return `https://www.first.org/cvss/calculator/3.1#${vector}`
}

export function cweUrl(cwe) {
  const id = cwe?.replace(/^CWE-/, '')
  return id ? `https://cwe.mitre.org/data/definitions/${id}.html` : null
}
