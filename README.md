```
  █████╗ ██╗   ██╗███████╗
 ██╔══██╗██║   ██║██╔════╝
 ███████║██║   ██║███████╗
 ██╔══██║╚██╗ ██╔╝╚════██║
 ██║  ██║ ╚████╔╝ ███████║
 ╚═╝  ╚═╝  ╚═══╝  ╚══════╝
  ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗███████╗
  ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔════╝██╔════╝
  █████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║     ███████╗
  ██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║     ╚════██║
  ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╗███████║
  ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝╚══════╝
```

# AVSForensics v0.1.0

Herramienta de análisis forense de metadatos digitales para **auditorías e investigación educativa**.  
Construida en Python 3.11 — analiza imágenes, documentos, audio y video en busca de anomalías y evidencia de manipulación.

> ⚠️ **Uso exclusivo en archivos propios o con autorización explícita.**

---

## Características

| Módulo | Formatos | Descripción |
|---|---|---|
| `image_analyzer` | JPG, PNG, HEIC, TIFF, WEBP | EXIF, GPS, cámara, trazas de edición |
| `document_analyzer` | PDF, DOCX, XLSX, PPTX | Autor, fechas, software, revisiones |
| `media_analyzer` | MP4, MP3, AVI, MKV, FLAC | Codec, bitrate, dispositivo, GPS |
| `base_analyzer` | Todos | Hash MD5/SHA256, magic bytes, fechas del sistema |
| `manipulation_detector` | Todos | Inconsistencias entre metadatos y sistema |

---

## Detección forense

- **Magic bytes** — detecta archivos renombrados (un `.exe` disfrazado de `.jpg`)
- **GPS** — extrae coordenadas y genera link a Google Maps
- **Trazas de edición** — detecta Photoshop, GIMP, Lightroom y otros editores
- **Manipulación de fechas** — compara fecha del sistema vs metadatos internos
- **Author mismatch** — detecta cuando el autor original ≠ último editor
- **Fecha futura** — metadatos con fechas imposibles

---

## Instalación

```bash
git clone https://github.com/averas232-pixel/AVSForensics.git
cd AVSForensics

python -m venv .venv

# Windows:
.venv\Scripts\Activate.ps1
# Linux/Mac:
source .venv/bin/activate

pip install -r requirements.txt
```

---

## Uso

```bash
# Analizar una imagen
python main.py --target foto.jpg

# Analizar un documento
python main.py --target informe.pdf

# Analizar un video
python main.py --target video.mp4

# Analizar una carpeta completa
python main.py --target C:\fotos\

# Recursivo en subcarpetas
python main.py --target C:\documentos\ --recursive

# Solo metadatos
python main.py --target foto.jpg --modules meta

# Solo hashes
python main.py --target foto.jpg --modules hash

# Exportar reporte
python main.py --target foto.jpg --out markdown
python main.py --target foto.jpg --out pdf
```

---

## Estructura del proyecto

```
AVSForensics/
├── main.py                        # Entrypoint CLI
├── config.py                      # Extensiones, flags, thresholds
├── requirements.txt
├── analyzers/
│   ├── base_analyzer.py           # Hashes, magic bytes, fechas del sistema
│   ├── image_analyzer.py          # EXIF, GPS, cámara
│   ├── document_analyzer.py       # PDF, DOCX, XLSX, PPTX
│   └── media_analyzer.py          # MP4, MP3, AVI, MKV, FLAC
├── forensics/
│   └── manipulation_detector.py   # Detección cruzada de anomalías
├── reports/
│   └── report_generator.py        # Exporta Markdown y PDF
└── utils/
    ├── logger.py                   # Rich: colores por severidad
    └── file_utils.py               # Magic bytes, hashes, collect targets
```

---

## Stack técnico

- **Python 3.11** — lenguaje principal
- **Pillow** — propiedades de imagen
- **exifread** — EXIF extendido y GPS
- **pymupdf** — metadatos de PDF
- **python-docx / openpyxl** — metadatos de Word y Excel
- **mutagen** — audio y video
- **Rich** — terminal con colores y severidad
- **fpdf2** — reportes PDF

---

## Autor

**Antony Vera Sanchez** — [@averas232-pixel](https://github.com/averas232-pixel)  
Proyecto educativo — portafolio de ciberseguridad y forense digital
