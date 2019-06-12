#include "testutils.h"
#include <wchar.h>

/*lint -save -e1055 */
/*lint -save -e586 */
/*lint -save -e534 */
/*lint -e686 */
wint_t get_response()
{
	wint_t r;
	r = (wint_t)getwchar();
	return r;
}
/*lint -restore */