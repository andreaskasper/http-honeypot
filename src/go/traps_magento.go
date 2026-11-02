package main

import (
	"fmt"
	"net/http"
	"strings"
)

// magentoTrap covers "PolyShell", CVE-2026-48356, the unrestricted file upload
// in Adobe Commerce and Magento Open Source. A guest (anonymous) shopping cart
// accepts an item with a file-type custom option, Magento writes the
// base64-encoded file data below pub/media/custom_options/quote/ without
// checking the extension, and the only guard is an image-header check that a
// polyglot GIF/PNG-with-PHP file passes. Sansec first saw mass scanning on
// 2026-03-19; Adobe published APSB26-73 on 2026-07-14; CISA added the CVE to
// the KEV catalog on 2026-10-27 after Sansec tied it to a content-block loader
// campaign. The dropped shells (index.php, bypass.php, c.php, rce.php, ...)
// sit next to the uploaded image.
//
// The request shape is the public Magento REST API, so the paths are the
// documented guest-cart routes:
//
//	POST /rest/V1/guest-carts                        (creates a cart)
//	POST /rest/default/V1/guest-carts/<id>/items     (adds the item + file option)
//
// Two tags:
//
//   - magento-polyshell-upload — any /rest/[<store>/]V1/guest-carts... path. The
//     cart-creation call is answered with a quoted cart id, every other call
//     with a cart-item document, so the attacker believes the upload landed.
//
//   - magento-polyshell-scan — anything under /pub/media/custom_options/, where
//     the attacker looks for the file he just "uploaded". Answered with a bare
//     GIF header, the first bytes of a polyglot.
//
// Deliberately not claimed: the rest of /rest/ (every Magento shop serves its
// catalogue there) and the rest of /pub/media/.
//
// The request body is never read and nothing is stored; every response is
// fabricated.
func magentoTrap(w http.ResponseWriter, r *http.Request, info *HoneypotRequest) bool {
	p := strings.TrimSuffix(strings.ToLower(r.URL.Path), "/")

	switch {
	case strings.HasPrefix(p, "/rest/") && strings.Contains(p, "/v1/guest-carts"):
		markAttack(info, "magento-polyshell-upload")
		cartID := getMD5Hash(info.ip + "-magento-guest-cart")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if strings.HasSuffix(p, "/v1/guest-carts") {
			fmt.Fprintf(w, "%q", cartID)
			return true
		}
		fmt.Fprintf(w, `{"item_id":4711,"sku":"24-MB01","qty":1,"name":"Joust Duffle Bag",`+
			`"price":34,"product_type":"simple","quote_id":%q}`, cartID)
		return true

	case strings.HasPrefix(p, "/pub/media/custom_options/"):
		markAttack(info, "magento-polyshell-scan")
		w.Header().Set("Content-Type", "image/gif")
		fmt.Fprint(w, "GIF89a")
		return true
	}
	return false
}
