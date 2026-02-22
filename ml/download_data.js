import fs from 'fs';
import path from 'path';
import axios from 'axios';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const url = 'https://raw.githubusercontent.com/harrypro02/Android-Malware-Permission-Based-Dataset/master/Permission_DATASET.csv';
const outputPath = path.join(__dirname, 'dataset.csv');

console.log(`Downloading dataset from ${url}...`);

axios({
    method: 'get',
    url: url,
    responseType: 'stream',
})
    .then((response) => {
        const writer = fs.createWriteStream(outputPath);
        response.data.pipe(writer);

        writer.on('finish', () => {
            console.log(`Dataset downloaded successfully to ${outputPath}`);
        });

        writer.on('error', (err) => {
            console.error(`Error writing to file: ${err.message}`);
        });
    })
    .catch((err) => {
        console.error(`Error downloading dataset: ${err.message}`);
    });
