import argparse
import sys
import datetime
from pathlib import Path
from forensic_image import analyze, verify, ImageEvidence

parser = argparse.ArgumentParser(description="Enter the path to the image file to analyze.")
parser.add_argument("image_path", help="Usage: python main.py <image_path>")
args = parser.parse_args()

# 1. Verifying path of the image
try:
    image_path = Path(args.image_path)
except Exception as e:
    print(f"Error occurred while verifying the image path: {e}")
    sys.exit(1)    

# 2. High-level analysis
report = analyze(image_path)

# 3. Inspect cryptographic digests & dimensions
print(f"SHA-256: {report.hashes.sha256}")
print(f"Dimensions: {report.file.width} x {report.file.height}")

# 4. Inspect metadata
if report.metadata.exif.is_present:
    print(f"Camera: {report.metadata.exif.make} {report.metadata.exif.model}")
    print(f"Capture Time: {report.metadata.exif.date_time_original}")

if report.metadata.exif.gps.has_coordinates:
    print(f"Coordinates: {report.metadata.exif.gps.latitude}, {report.metadata.exif.gps.longitude}")

# 5. Review forensic findings
for finding in report.findings.items:
    print(f"[{finding.status.value}] [{finding.severity.value}] {finding.title}")
    if finding.limitations:
        print(f"  Limitations: {finding.limitations}")

# 6. Export interactive HTML or JSON reports
report.save_html(f"forensic_report_{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.html")
report.save_json(f"forensic_report_{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.json")