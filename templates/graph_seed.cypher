// Initial Schema Setup for AmegakureWotan Graph
CREATE CONSTRAINT unique_entity_value IF NOT EXISTS
FOR (e:Entity) REQUIRE e.value IS UNIQUE;

CREATE INDEX entity_id_idx IF NOT EXISTS
FOR (e:Entity) ON (e.id);
