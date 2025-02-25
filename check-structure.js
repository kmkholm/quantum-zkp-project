const fs = require('fs');
const path = require('path');

// Check project structure
function checkStructure() {
    const rootDir = process.cwd();
    
    // Required directories
    const dirs = ['contracts', 'migrations'];
    
    // Required files
    const files = {
        contracts: ['Migrations.sol', 'IoTQuantumZKPStorage.sol'],
        migrations: ['1_initial_migration.js', '2_deploy_contracts.js'],
        root: ['truffle-config.js', 'package.json']
    };
    
    console.log('Checking project structure...\n');
    
    // Check directories
    dirs.forEach(dir => {
        if (!fs.existsSync(path.join(rootDir, dir))) {
            console.error(`❌ Missing directory: ${dir}`);
        } else {
            console.log(`✓ Found directory: ${dir}`);
            
            // Check files in directory
            files[dir].forEach(file => {
                if (!fs.existsSync(path.join(rootDir, dir, file))) {
                    console.error(`  ❌ Missing file: ${dir}/${file}`);
                } else {
                    console.log(`  ✓ Found file: ${dir}/${file}`);
                }
            });
        }
    });
    
    // Check root files
    files.root.forEach(file => {
        if (!fs.existsSync(path.join(rootDir, file))) {
            console.error(`❌ Missing file: ${file}`);
        } else {
            console.log(`✓ Found file: ${file}`);
        }
    });
}

checkStructure();