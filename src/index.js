"use strict";

const BASIC_USER = 'admin';
const BASIC_PASS = 'admin';

var key = '',
    value = '',
    body = {};

addEventListener( 'fetch', event => {
	return event.respondWith( handleRequest( event ).catch( err => {
		const message = err.reason || err.stack || 'Unknown error';

		return new Response( message, {
			status: err.status || 500,
			statusText: err.statusText || null,
			headers: {
				'Content-Type': 'text/plain;charset=UTF-8',
				'Cache-Control': 'no-store',
				'Content-Length': message.length,
			},
		} );
	} ) );
} );

async function handleRequest( event ) {
	const { protocol, pathname } = new URL( event.request.url );

	if ( 'https:' !== protocol || 'https' !== event.request.headers.get( 'x-forwarded-proto' ) ) {
		throw new BadRequestException( 'Please use an HTTPS connection.' );
	}

	if ( event.request.headers.has( 'Authorization' ) ) {
		const { user, pass } = basicAuthentication( event.request );
		verifyCredentials( user, pass );

		if ( 'POST' === event.request.method.toUpperCase() ) {
			return handlePostRequest( event );
		}

		return handleGetRequest( event );
	}

	return new Response( null, {
		status: 401,
		headers: {
			'WWW-Authenticate': 'Basic realm="GitHub Deployments", charset="UTF-8"',
		},
	} );
}

async function handlePostRequest( event ) {
	const request = event.request;
	const body = await request.json();

	key   = body?.environment;
	value = body?.branch;

	if ( ! key || ! value ) {
		return new Response( null, {
			status: 400,
		} );
	}

	await storage.put( key, value );

	return new Response( null, {
		status: 200,
		headers: {
			'Cache-Control': 'no-store',
		}
	} );
}

async function handleGetRequest( event ) {
	const list = await storage.list();

	for ( key of list.keys ) {
		value = await storage.get( key.name );
		body[ key.name ] = value;
	}

	return new Response( JSON.stringify( body ), {
		status: 200,
		headers: {
			'Cache-Control': 'no-store',
		}
	} );
}

/**
 * Throws exception on verification failure.
 * @param {string} user
 * @param {string} pass
 * @throws {UnauthorizedException}
 */
function verifyCredentials(user, pass) {
	if (BASIC_USER !== user) {
		throw new UnauthorizedException( 'Invalid credentials.' );
	}

	if (BASIC_PASS !== pass) {
		throw new UnauthorizedException( 'Invalid credentials.' );
	}
}

/**
 * Parse HTTP Basic Authorization value.
 * @param {Request} request
 * @throws {BadRequestException}
 * @returns {{ user: string, pass: string }}
 */
function basicAuthentication(request) {
	const Authorization = request.headers.get('Authorization');

	const [scheme, encoded] = Authorization.split(' ');

	// The Authorization header must start with Basic, followed by a space.
	if (!encoded || scheme !== 'Basic') {
		throw new BadRequestException('Malformed authorization header.');
	}

	// Decodes the base64 value and performs unicode normalization.
	// @see https://datatracker.ietf.org/doc/html/rfc7613#section-3.3.2 (and #section-4.2.2)
	// @see https://dev.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String/normalize
	const buffer = Uint8Array.from(atob(encoded), character => character.charCodeAt(0));
	const decoded = new TextDecoder().decode(buffer).normalize();

	// The username & password are split by the first colon.
	//=> example: "username:password"
	const index = decoded.indexOf(':');

	// The user & password are split by the first colon and MUST NOT contain control characters.
	// @see https://tools.ietf.org/html/rfc5234#appendix-B.1 (=> "CTL = %x00-1F / %x7F")
	if (index === -1 || /[\0-\x1F\x7F]/.test(decoded)) {
		throw new BadRequestException('Invalid authorization value.');
	}

	return {
		user: decoded.substring(0, index),
		pass: decoded.substring(index + 1),
	};
}

function UnauthorizedException(reason) {
	this.status = 401;
	this.statusText = 'Unauthorized';
	this.reason = reason;
}

function BadRequestException(reason) {
	this.status = 400;
	this.statusText = 'Bad Request';
	this.reason = reason;
}
