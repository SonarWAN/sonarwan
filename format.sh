for f in sonarwan/*.py; do
    yapf -i "$f"
done
