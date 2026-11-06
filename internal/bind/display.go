package bind

// DisplayPhrase maps a bind refusal onto one actionable, value-free sentence.
//
// Why it lives here: the vocabulary (categories, status codes) is owned by this
// package, so the mapping cannot drift from what Run actually returns. Callers
// only ever print the result.
//
// Why it exists at all: the connect command used to map exactly one case (409
// ticket_superseded) and print "an unexpected error occurred" for every other
// refusal. Reusing an already-applied connect link therefore looked like a
// collector crash instead of "get a new link".
func (e *Error) DisplayPhrase() string {
	if e == nil {
		return ""
	}
	switch e.category {
	case CategoryTicketSuperseded:
		return "this connect link has already been applied or is no longer valid (the authorization changed, or this device already used a newer link); generate a new connect link on the website and run it again"
	case CategoryTransport:
		return "the server could not be reached to bind this device; check connectivity and the server status"
	case CategoryInvalidResponse:
		return "the server's bind response could not be understood (a proxy or an incompatible server may be in the path)"
	case "unauthorized":
		return "the server rejected this connect link or device credential; generate a new connect link on the website and run it again"
	case "not_found":
		return "the server does not know this connect link; generate a new connect link on the website and run it again"
	case "conflict":
		return "this connect link was already used with a different request; generate a new connect link on the website and run it again"
	case "bad_request", "invalid_request":
		return "the server rejected the bind request as invalid; generate a new connect link on the website and run it again"
	case "rate_limited":
		return "the server is rate limiting connect attempts; wait a moment and run the same command again"
	case "server_error":
		return "the server reported an internal error while binding this device; try again shortly"
	case "redirect":
		return "the server answered with a redirect, which is never followed; check the server URL"
	}
	return ""
}
