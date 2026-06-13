ALTER TABLE programs ADD COLUMN average_fuel_consumed REAL;
ALTER TABLE programs ADD COLUMN fuel_samples INTEGER NOT NULL DEFAULT 0;
