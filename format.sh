for f in sonarwan/*.py; do
    yapf -i "$f"
done
for f in sonarwan/tools/*.py; do
    yapf -i "$f"
done
