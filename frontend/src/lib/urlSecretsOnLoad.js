// The first import of main.jsx: clears any secret from the address bar before
// any other code (the router, analytics, error reporting) can read the URL.
import { captureUrlSecrets } from './urlSecrets'

captureUrlSecrets()
