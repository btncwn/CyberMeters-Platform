// C-40b (Codex adversarial receipt on #926, item 15 B2): the Website Summary HSTS
// tile reads the engine's host-scoped hsts_policy — the apex's own HTTPS answer —
// never "not in missing + no strength". The 13 shapes below are the receipt's
// rows (headers trimmed to the fields the tile reads); synthetic example hosts.
import { describe, expect, it } from 'vitest'
import { hstsTile, headerAbsenceUncertain } from '../WebsiteScanOverview'

const ROWS = [
 {
  "name": "apex absent / www strong",
  "expect": "Not sent by the apex",
  "headers": {
   "accessible": true,
   "headers_assessed": true,
   "status_code": 200,
   "response_url": "https://www.review.example.com/",
   "final_https": true,
   "validation_uncertain": false,
   "present": [
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy"
   ],
   "missing": [
    "strict-transport-security"
   ],
   "hsts_policy": {
    "version": "2026-10-23.1",
    "apex_host": "review.example.com",
    "apex_url": "https://review.example.com",
    "apex_status": 301,
    "state": "absent",
    "value": null,
    "include_subdomains": false,
    "final_host": "www.review.example.com",
    "final_value": "max-age=31536000; includeSubDomains; preload",
    "final_covered": false
   },
   "checked_paths": [
    {
     "requested_url": "https://review.example.com",
     "final_url": "https://www.review.example.com/",
     "headers_observed": {
      "strict-transport-security": "max-age=31536000; includeSubDomains; preload"
     }
    },
    {
     "requested_url": "https://www.review.example.com/",
     "final_url": "https://www.review.example.com/",
     "headers_observed": {
      "strict-transport-security": "max-age=31536000; includeSubDomains; preload"
     }
    },
    {
     "requested_url": "https://www.review.example.com",
     "final_url": "https://www.review.example.com",
     "headers_observed": {
      "strict-transport-security": "max-age=31536000; includeSubDomains; preload"
     }
    }
   ]
  }
 },
 {
  "name": "apex absent / www short",
  "expect": "Not sent by the apex",
  "headers": {
   "accessible": true,
   "headers_assessed": true,
   "status_code": 200,
   "response_url": "https://www.review.example.com/",
   "final_https": true,
   "validation_uncertain": false,
   "present": [
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy"
   ],
   "missing": [
    "strict-transport-security"
   ],
   "hsts_policy": {
    "version": "2026-10-23.1",
    "apex_host": "review.example.com",
    "apex_url": "https://review.example.com",
    "apex_status": 301,
    "state": "absent",
    "value": null,
    "include_subdomains": false,
    "final_host": "www.review.example.com",
    "final_value": "max-age=900",
    "final_covered": false
   },
   "checked_paths": [
    {
     "requested_url": "https://review.example.com",
     "final_url": "https://www.review.example.com/",
     "headers_observed": {
      "strict-transport-security": "max-age=900"
     }
    },
    {
     "requested_url": "https://www.review.example.com/",
     "final_url": "https://www.review.example.com/",
     "headers_observed": {
      "strict-transport-security": "max-age=900"
     }
    },
    {
     "requested_url": "https://www.review.example.com",
     "final_url": "https://www.review.example.com",
     "headers_observed": {
      "strict-transport-security": "max-age=900"
     }
    }
   ]
  }
 },
 {
  "name": "apex strong includeSubDomains / www absent",
  "expect": "Sent",
  "headers": {
   "accessible": true,
   "headers_assessed": true,
   "status_code": 200,
   "response_url": "https://www.review.example.com/",
   "final_https": true,
   "validation_uncertain": false,
   "present": [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy"
   ],
   "missing": [],
   "hsts_policy": {
    "version": "2026-10-23.1",
    "apex_host": "review.example.com",
    "apex_url": "https://review.example.com",
    "apex_status": 301,
    "state": "present",
    "value": "max-age=31536000; includeSubDomains; preload",
    "include_subdomains": true,
    "final_host": "www.review.example.com",
    "final_value": null,
    "final_covered": true
   },
   "header_strength": {
    "strict-transport-security": {
     "status": "valid",
     "details": "max-age=31536000 (≥180 days)"
    }
   },
   "checked_paths": [
    {
     "requested_url": "https://review.example.com",
     "final_url": "https://www.review.example.com/",
     "headers_observed": {
      "strict-transport-security": null
     }
    },
    {
     "requested_url": "https://www.review.example.com/",
     "final_url": "https://www.review.example.com/",
     "headers_observed": {
      "strict-transport-security": null
     }
    },
    {
     "requested_url": "https://www.review.example.com",
     "final_url": "https://www.review.example.com",
     "headers_observed": {
      "strict-transport-security": null
     }
    }
   ]
  }
 },
 {
  "name": "apex strong host-only / www absent",
  "expect": "Sent",
  "headers": {
   "accessible": true,
   "headers_assessed": true,
   "status_code": 200,
   "response_url": "https://www.review.example.com/",
   "final_https": true,
   "validation_uncertain": false,
   "present": [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy"
   ],
   "missing": [],
   "hsts_policy": {
    "version": "2026-10-23.1",
    "apex_host": "review.example.com",
    "apex_url": "https://review.example.com",
    "apex_status": 301,
    "state": "present",
    "value": "max-age=31536000",
    "include_subdomains": false,
    "final_host": "www.review.example.com",
    "final_value": null,
    "final_covered": false
   },
   "header_strength": {
    "strict-transport-security": {
     "status": "valid",
     "details": "max-age=31536000 (≥180 days)"
    }
   },
   "checked_paths": [
    {
     "requested_url": "https://review.example.com",
     "final_url": "https://www.review.example.com/",
     "headers_observed": {
      "strict-transport-security": null
     }
    },
    {
     "requested_url": "https://www.review.example.com/",
     "final_url": "https://www.review.example.com/",
     "headers_observed": {
      "strict-transport-security": null
     }
    },
    {
     "requested_url": "https://www.review.example.com",
     "final_url": "https://www.review.example.com",
     "headers_observed": {
      "strict-transport-security": null
     }
    }
   ]
  }
 },
 {
  "name": "apex strong / www short",
  "expect": "Sent",
  "headers": {
   "accessible": true,
   "headers_assessed": true,
   "status_code": 200,
   "response_url": "https://www.review.example.com/",
   "final_https": true,
   "validation_uncertain": false,
   "present": [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy"
   ],
   "missing": [],
   "hsts_policy": {
    "version": "2026-10-23.1",
    "apex_host": "review.example.com",
    "apex_url": "https://review.example.com",
    "apex_status": 301,
    "state": "present",
    "value": "max-age=31536000; includeSubDomains; preload",
    "include_subdomains": true,
    "final_host": "www.review.example.com",
    "final_value": "max-age=900",
    "final_covered": true
   },
   "header_strength": {
    "strict-transport-security": {
     "status": "valid",
     "details": "max-age=31536000 (≥180 days)"
    }
   },
   "checked_paths": [
    {
     "requested_url": "https://review.example.com",
     "final_url": "https://www.review.example.com/",
     "headers_observed": {
      "strict-transport-security": "max-age=900"
     }
    },
    {
     "requested_url": "https://www.review.example.com/",
     "final_url": "https://www.review.example.com/",
     "headers_observed": {
      "strict-transport-security": "max-age=900"
     }
    },
    {
     "requested_url": "https://www.review.example.com",
     "final_url": "https://www.review.example.com",
     "headers_observed": {
      "strict-transport-security": "max-age=900"
     }
    }
   ]
  }
 },
 {
  "name": "apex short / www strong",
  "expect": "Sent, weak",
  "headers": {
   "accessible": true,
   "headers_assessed": true,
   "status_code": 200,
   "response_url": "https://www.review.example.com/",
   "final_https": true,
   "validation_uncertain": false,
   "present": [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy"
   ],
   "missing": [],
   "hsts_policy": {
    "version": "2026-10-23.1",
    "apex_host": "review.example.com",
    "apex_url": "https://review.example.com",
    "apex_status": 301,
    "state": "present",
    "value": "max-age=900",
    "include_subdomains": false,
    "final_host": "www.review.example.com",
    "final_value": "max-age=31536000; includeSubDomains; preload",
    "final_covered": false
   },
   "header_strength": {
    "strict-transport-security": {
     "status": "weak",
     "details": "max-age=900 — below recommended minimum of 15,552,000 (180 days)"
    }
   },
   "checked_paths": [
    {
     "requested_url": "https://review.example.com",
     "final_url": "https://www.review.example.com/",
     "headers_observed": {
      "strict-transport-security": "max-age=31536000; includeSubDomains; preload"
     }
    },
    {
     "requested_url": "https://www.review.example.com/",
     "final_url": "https://www.review.example.com/",
     "headers_observed": {
      "strict-transport-security": "max-age=31536000; includeSubDomains; preload"
     }
    },
    {
     "requested_url": "https://www.review.example.com",
     "final_url": "https://www.review.example.com",
     "headers_observed": {
      "strict-transport-security": "max-age=31536000; includeSubDomains; preload"
     }
    }
   ]
  }
 },
 {
  "name": "apex max-age zero / www strong",
  "expect": "Sent, malformed",
  "headers": {
   "accessible": true,
   "headers_assessed": true,
   "status_code": 200,
   "response_url": "https://www.review.example.com/",
   "final_https": true,
   "validation_uncertain": false,
   "present": [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy"
   ],
   "missing": [],
   "hsts_policy": {
    "version": "2026-10-23.1",
    "apex_host": "review.example.com",
    "apex_url": "https://review.example.com",
    "apex_status": 301,
    "state": "present",
    "value": "max-age=0",
    "include_subdomains": false,
    "final_host": "www.review.example.com",
    "final_value": "max-age=31536000; includeSubDomains; preload",
    "final_covered": false
   },
   "header_strength": {
    "strict-transport-security": {
     "status": "malformed",
     "details": "max-age=0 disables HSTS protection"
    }
   },
   "checked_paths": [
    {
     "requested_url": "https://review.example.com",
     "final_url": "https://www.review.example.com/",
     "headers_observed": {
      "strict-transport-security": "max-age=31536000; includeSubDomains; preload"
     }
    },
    {
     "requested_url": "https://www.review.example.com/",
     "final_url": "https://www.review.example.com/",
     "headers_observed": {
      "strict-transport-security": "max-age=31536000; includeSubDomains; preload"
     }
    },
    {
     "requested_url": "https://www.review.example.com",
     "final_url": "https://www.review.example.com",
     "headers_observed": {
      "strict-transport-security": "max-age=31536000; includeSubDomains; preload"
     }
    }
   ]
  }
 },
 {
  "name": "apex never HTTPS / HTTP redirect www strong",
  "expect": "Not observed",
  "headers": {
   "accessible": true,
   "headers_assessed": true,
   "status_code": 200,
   "response_url": "https://www.review.example.com/",
   "final_https": true,
   "validation_uncertain": false,
   "present": [
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy"
   ],
   "missing": [],
   "hsts_policy": {
    "version": "2026-10-23.1",
    "apex_host": "review.example.com",
    "apex_url": "https://review.example.com",
    "apex_status": null,
    "state": "not_observed",
    "value": null,
    "include_subdomains": false,
    "final_host": "www.review.example.com",
    "final_value": "max-age=31536000; includeSubDomains; preload",
    "final_covered": false
   },
   "checked_paths": [
    {
     "requested_url": "http://review.example.com",
     "final_url": "https://www.review.example.com/",
     "headers_observed": {
      "strict-transport-security": "max-age=31536000; includeSubDomains; preload"
     }
    },
    {
     "requested_url": "https://www.review.example.com/",
     "final_url": "https://www.review.example.com/",
     "headers_observed": {
      "strict-transport-security": "max-age=31536000; includeSubDomains; preload"
     }
    },
    {
     "requested_url": "http://www.review.example.com",
     "final_url": "http://www.review.example.com",
     "headers_observed": {
      "strict-transport-security": "max-age=31536000; includeSubDomains; preload"
     }
    }
   ]
  }
 },
 {
  "name": "HTTP-only HSTS / www absent",
  "expect": "Not observed",
  "headers": {
   "accessible": true,
   "headers_assessed": true,
   "status_code": 200,
   "response_url": "https://www.review.example.com/",
   "final_https": true,
   "validation_uncertain": false,
   "present": [
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy"
   ],
   "missing": [],
   "hsts_policy": {
    "version": "2026-10-23.1",
    "apex_host": "review.example.com",
    "apex_url": "https://review.example.com",
    "apex_status": null,
    "state": "not_observed",
    "value": null,
    "include_subdomains": false,
    "final_host": "www.review.example.com",
    "final_value": null,
    "final_covered": false
   },
   "checked_paths": [
    {
     "requested_url": "http://review.example.com",
     "final_url": "https://www.review.example.com/",
     "headers_observed": {
      "strict-transport-security": null
     }
    },
    {
     "requested_url": "https://www.review.example.com/",
     "final_url": "https://www.review.example.com/",
     "headers_observed": {
      "strict-transport-security": null
     }
    },
    {
     "requested_url": "http://www.review.example.com",
     "final_url": "http://www.review.example.com",
     "headers_observed": {
      "strict-transport-security": null
     }
    }
   ]
  }
 },
 {
  "name": "direct apex strong",
  "expect": "Sent",
  "headers": {
   "accessible": true,
   "headers_assessed": true,
   "status_code": 200,
   "response_url": "https://review.example.com",
   "final_https": true,
   "validation_uncertain": false,
   "present": [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy"
   ],
   "missing": [],
   "hsts_policy": {
    "version": "2026-10-23.1",
    "apex_host": "review.example.com",
    "apex_url": "https://review.example.com",
    "apex_status": 200,
    "state": "present",
    "value": "max-age=31536000; includeSubDomains; preload",
    "include_subdomains": true,
    "final_host": "review.example.com",
    "final_value": "max-age=31536000; includeSubDomains; preload",
    "final_covered": true
   },
   "header_strength": {
    "strict-transport-security": {
     "status": "valid",
     "details": "max-age=31536000 (≥180 days)"
    }
   },
   "checked_paths": [
    {
     "requested_url": "https://review.example.com",
     "final_url": "https://review.example.com",
     "headers_observed": {
      "strict-transport-security": "max-age=31536000; includeSubDomains; preload"
     }
    },
    {
     "requested_url": "https://www.review.example.com",
     "final_url": "https://www.review.example.com",
     "headers_observed": {
      "strict-transport-security": null
     }
    }
   ]
  }
 },
 {
  "name": "direct apex absent",
  "expect": "Not sent",
  "headers": {
   "accessible": true,
   "headers_assessed": true,
   "status_code": 200,
   "response_url": "https://review.example.com",
   "final_https": true,
   "validation_uncertain": false,
   "present": [
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy"
   ],
   "missing": [
    "strict-transport-security"
   ],
   "hsts_policy": {
    "version": "2026-10-23.1",
    "apex_host": "review.example.com",
    "apex_url": "https://review.example.com",
    "apex_status": 200,
    "state": "absent",
    "value": null,
    "include_subdomains": false,
    "final_host": "review.example.com",
    "final_value": null,
    "final_covered": true
   },
   "checked_paths": [
    {
     "requested_url": "https://review.example.com",
     "final_url": "https://review.example.com",
     "headers_observed": {
      "strict-transport-security": null
     }
    },
    {
     "requested_url": "https://www.review.example.com",
     "final_url": "https://www.review.example.com",
     "headers_observed": {
      "strict-transport-security": null
     }
    }
   ]
  }
 },
 {
  "name": "corpus-79 recorded HSTS replay",
  "expect": "Sent",
  "headers": {
   "accessible": true,
   "headers_assessed": true,
   "status_code": 200,
   "response_url": "https://www.review.example.com/",
   "final_https": true,
   "validation_uncertain": false,
   "present": [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy"
   ],
   "missing": [],
   "hsts_policy": {
    "version": "2026-10-23.1",
    "apex_host": "review.example.com",
    "apex_url": "https://review.example.com",
    "apex_status": 301,
    "state": "present",
    "value": "max-age=31536000; includeSubdomains; preload",
    "include_subdomains": true,
    "final_host": "www.review.example.com",
    "final_value": "max-age=900",
    "final_covered": true
   },
   "header_strength": {
    "strict-transport-security": {
     "status": "valid",
     "details": "max-age=31536000 (≥180 days)"
    }
   },
   "checked_paths": [
    {
     "requested_url": "https://review.example.com",
     "final_url": "https://www.review.example.com/",
     "headers_observed": {
      "strict-transport-security": "max-age=900"
     }
    },
    {
     "requested_url": "https://www.review.example.com/",
     "final_url": "https://www.review.example.com/",
     "headers_observed": {
      "strict-transport-security": "max-age=900"
     }
    },
    {
     "requested_url": "https://www.review.example.com",
     "final_url": "https://www.review.example.com",
     "headers_observed": {
      "strict-transport-security": "max-age=900"
     }
    }
   ]
  }
 },
 {
  "name": "corpus-60 recorded HSTS replay",
  "expect": "Sent",
  "headers": {
   "accessible": true,
   "headers_assessed": true,
   "status_code": 200,
   "response_url": "https://www.review.example.com/",
   "final_https": true,
   "validation_uncertain": false,
   "present": [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy"
   ],
   "missing": [],
   "hsts_policy": {
    "version": "2026-10-23.1",
    "apex_host": "review.example.com",
    "apex_url": "https://review.example.com",
    "apex_status": 301,
    "state": "present",
    "value": "max-age=63072000; includeSubDomains; preload",
    "include_subdomains": true,
    "final_host": "www.review.example.com",
    "final_value": "max-age=86400",
    "final_covered": true
   },
   "header_strength": {
    "strict-transport-security": {
     "status": "valid",
     "details": "max-age=63072000 (≥180 days)"
    }
   },
   "checked_paths": [
    {
     "requested_url": "https://review.example.com",
     "final_url": "https://www.review.example.com/",
     "headers_observed": {
      "strict-transport-security": "max-age=86400"
     }
    },
    {
     "requested_url": "https://www.review.example.com/",
     "final_url": "https://www.review.example.com/",
     "headers_observed": {
      "strict-transport-security": "max-age=86400"
     }
    },
    {
     "requested_url": "https://www.review.example.com",
     "final_url": "https://www.review.example.com",
     "headers_observed": {
      "strict-transport-security": "max-age=86400"
     }
    }
   ]
  }
 }
]

describe('HSTS tile from hsts_policy (receipt shapes)', () => {
  for (const row of ROWS) {
    it(`${row.name} → ${row.expect}`, () => {
      expect(hstsTile(row.headers, true).value).toBe(row.expect)
    })
  }
})

describe('the three cases the Executive named', () => {
  const byName = (n) => ROWS.find((r) => r.name === n).headers
  it('(1) apex never answered HTTPS → "Not observed" with the sentence, never "Sent"', () => {
    const t = hstsTile(byName('apex never HTTPS / HTTP redirect www strong'), true)
    expect(t.value).toBe('Not observed')
    expect(t.note).toBe('The apex did not answer over HTTPS this scan; its HSTS policy was not observed.')
  })
  it('(2) apex answered without HSTS while www sends it → "Not sent by the apex", naming www; never "Not validated"', () => {
    const t = hstsTile(byName('apex absent / www strong'), true)
    expect(t.value).toBe('Not sent by the apex')
    expect(t.note).toContain('www.review.example.com')
    expect(t.value).not.toBe('Not validated')
  })
  it('(3) apex sends it → strength from the apex policy', () => {
    expect(hstsTile(byName('direct apex strong'), true)).toMatchObject({ value: 'Sent', note: expect.stringContaining('max-age=31536000') })
    expect(hstsTile(byName('apex short / www strong'), true).value).toBe('Sent, weak')
  })
  it('a host-only apex policy says it does not cover the final host', () => {
    expect(hstsTile(byName('apex strong host-only / www absent'), true).note).toContain('without includeSubDomains, so it does not cover www.review.example.com')
  })
  it('"Not validated" only from the module\'s own uncertainty flag', () => {
    const h = { ...byName('apex absent / www strong'), validation_uncertain: true }
    expect(hstsTile(h, true).value).toBe('Not validated')
  })
  it('headers not assessed → "Not confirmed"', () => {
    expect(hstsTile(byName('direct apex strong'), false).value).toBe('Not confirmed')
  })
})

describe('legacy results (no hsts_policy) and the checked-paths heuristic', () => {
  const legacy = (over) => ({ accessible: true, headers_assessed: true, status_code: 200, final_https: true, validation_uncertain: false,
    response_url: 'https://www.review.example.com/', present: [], missing: ['strict-transport-security'], checked_paths: [], ...over })
  it('a legacy result keeps the header-based tile', () => {
    expect(hstsTile(legacy(), true).value).toBe('Not sent')
  })
  it('another host\'s header is not page variation', () => {
    const h = legacy({ checked_paths: [{ requested_url: 'https://review.example.com', final_url: 'https://other.example.net/', headers_observed: { 'strict-transport-security': 'max-age=31536000' } }] })
    expect(headerAbsenceUncertain(h, 'strict-transport-security')).toBe(false)
  })
  it('the same host varying by page still is', () => {
    const h = legacy({ checked_paths: [{ requested_url: 'https://www.review.example.com/login', final_url: 'https://www.review.example.com/login', headers_observed: { 'strict-transport-security': 'max-age=31536000' } }] })
    expect(headerAbsenceUncertain(h, 'strict-transport-security')).toBe(true)
  })
})
