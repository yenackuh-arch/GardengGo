-- =====================================================================
-- GardenGo starting catalog (OPTIONAL). Run AFTER schema.sql.
-- Adds the 4 categories and the 12 starter plants from the website.
-- No customers, orders, or revenue are created. Safe to run again (duplicates are skipped).
-- Photos use the same web links as the website for now. The admin can upload real photos later.
-- =====================================================================
USE gardengo;

INSERT IGNORE INTO categories (name) VALUES ('Indoor'), ('Outdoor'), ('Succulent'), ('Flowering');

INSERT IGNORE INTO plants (category_id, name, description, price, stock_quantity, image_path) VALUES
((SELECT id FROM categories WHERE name='Indoor'),    'Monstera Deliciosa',   'Large split leaves; a bold statement for bright indoor corners.',          450.00, 12, 'https://images.unsplash.com/photo-1459411552884-841db9b3cc2a?auto=format&fit=crop&w=600&q=70'),
((SELECT id FROM categories WHERE name='Indoor'),    'Snake Plant',          'Hardy and low-maintenance. Tolerates low light and missed watering.',      280.00, 25, 'https://images.unsplash.com/photo-1509423350716-97f9360b4e09?auto=format&fit=crop&w=600&q=70'),
((SELECT id FROM categories WHERE name='Succulent'), 'Echeveria Succulent',  'Rosette-shaped succulent, perfect for desks and sunny windowsills.',       120.00, 40, 'https://images.unsplash.com/photo-1485955900006-10f4d324d411?auto=format&fit=crop&w=600&q=70'),
((SELECT id FROM categories WHERE name='Outdoor'),   'Pink Bougainvillea',   'Vibrant papery blooms. Loves full sun and thrives in Laguna weather.',     350.00,  8, 'https://images.unsplash.com/photo-1459156212016-c812468e2115?auto=format&fit=crop&w=600&q=70'),
((SELECT id FROM categories WHERE name='Indoor'),    'Boston Fern',          'Lush, feathery fronds that freshen up shaded spaces.',                     220.00,  4, 'https://images.unsplash.com/photo-1453904300235-0f2f60b15b5d?auto=format&fit=crop&w=600&q=70'),
((SELECT id FROM categories WHERE name='Succulent'), 'Golden Barrel Cactus', 'Round, sun-loving cactus with golden spines. Needs little water.',          300.00, 15, 'https://images.unsplash.com/photo-1463320726281-696a485928c7?auto=format&fit=crop&w=600&q=70'),
((SELECT id FROM categories WHERE name='Indoor'),    'Peace Lily',           'Elegant white blooms and glossy leaves for shaded rooms.',                 320.00, 10, 'https://images.unsplash.com/photo-1520412099551-62b6bafdf9a0?auto=format&fit=crop&w=600&q=70'),
((SELECT id FROM categories WHERE name='Outdoor'),   'Yellow Ixora',         'Clusters of bright flowers; a favorite for garden borders.',               180.00,  0, 'https://images.unsplash.com/photo-1501004318641-b39e6451bec6?auto=format&fit=crop&w=600&q=70'),
((SELECT id FROM categories WHERE name='Succulent'), 'Aloe Vera',            'Easy-care succulent with soothing gel-filled leaves.',                     150.00, 30, 'https://images.unsplash.com/photo-1512428813834-c702c7702b78?auto=format&fit=crop&w=600&q=70'),
((SELECT id FROM categories WHERE name='Indoor'),    'Rubber Plant',         'Thick, glossy dark leaves. Grows tall and sturdy indoors.',                380.00,  3, 'https://images.unsplash.com/photo-1470058869958-2a77ade41c02?auto=format&fit=crop&w=600&q=70'),
((SELECT id FROM categories WHERE name='Flowering'), 'Assorted Orchids',     'Long-lasting orchid blooms in assorted colors.',                           550.00,  9, 'https://images.unsplash.com/photo-1416879595882-3373a0480b5b?auto=format&fit=crop&w=600&q=70'),
((SELECT id FROM categories WHERE name='Outdoor'),   'Santan (Ixora Red)',   'Hardy flowering shrub that attracts butterflies to your garden.',          160.00, 20, 'https://images.unsplash.com/photo-1466692476868-aef1dfb1e735?auto=format&fit=crop&w=600&q=70');

-- Record the opening stock in the history (only for plants that have no history yet)
INSERT INTO stock_movements (plant_id, movement_type, quantity_change, balance_after, note)
SELECT p.id, 'initial_stock', p.stock_quantity, p.stock_quantity, 'Opening stock'
FROM plants p
WHERE p.stock_quantity > 0
  AND NOT EXISTS (SELECT 1 FROM stock_movements m WHERE m.plant_id = p.id);
