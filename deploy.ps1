Remove-Item fetchDocs.mjs -ErrorAction SilentlyContinue
Remove-Item fetched_community.txt -ErrorAction SilentlyContinue
if (!(git config user.email)) { git config user.email "bot@omnisec.dev" }
if (!(git config user.name)) { git config user.name "OmniSec Deployer" }
git init
git add .
git commit -m "feat: complete Tier S Exec-Mode Multi-API OmniSec Normalizer"
git branch -M main
git remote remove origin 2>$null
git remote add origin https://github.com/UncleSam-tech/omnisec.git
git push -u origin main
