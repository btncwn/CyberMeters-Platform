import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { expect, it } from 'vitest'

it('links both account billing prompts to the live billing route', () => {
  const file = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'AccountPage.jsx')
  const source = fs.readFileSync(file, 'utf8')
  expect(source).not.toContain('Billing available in an upcoming release')
  expect(source.match(/<Link to="\/billing"/g)).toHaveLength(2)
})
